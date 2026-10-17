// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! UAT Page Table management
//!
//! AGX GPUs use an MMU called the UAT, which is largely compatible with the ARM64 page table
//! format. This module manages the actual page tables by allocating raw memory pages from
//! the kernel page allocator.

use core::fmt::Debug;
use core::mem::size_of;
use core::ops::Range;
use core::sync::atomic::{
    AtomicU64,
    Ordering, //
};

use kernel::{
    addr::PhysicalAddr,
    error::Result,
    page::Page,
    prelude::*, //
};

use crate::debug::*;
use crate::util::align;

const DEBUG_CLASS: DebugFlags = DebugFlags::PgTable;

/// Number of bits in a page offset.
pub(crate) const UAT_PGBIT: usize = 14;
/// UAT page size.
pub(crate) const UAT_PGSZ: usize = 1 << UAT_PGBIT;
/// UAT page offset mask.
pub(crate) const UAT_PGMSK: usize = UAT_PGSZ - 1;

type Pte = AtomicU64;

const PTE_BIT: usize = 3; // log2(sizeof(Pte))
const PTE_SIZE: usize = 1 << PTE_BIT;

/// Number of PTEs per page.
const UAT_NPTE: usize = UAT_PGSZ / size_of::<Pte>();

/// Number of address bits to address a level
const UAT_LVBIT: usize = UAT_PGBIT - PTE_BIT;
/// Number of entries per level
const UAT_LVSZ: usize = UAT_NPTE;
/// Mask of level bits
const UAT_LVMSK: u64 = (UAT_LVSZ - 1) as u64;

const UAT_LEVELS: usize = 3;

/// UAT input address space, per region. G15 has two 42-bit regions; bit 42
/// of the VA selects region 1, and the GPTBAT holds one table base per
/// region (spec/agx-g15c/uat.md).
pub(crate) const UAT_IAS: usize = 42;
const UAT_IASMSK: u64 = (1u64 << UAT_IAS) - 1;

const PTE_TYPE_BITS: u64 = 3;
const PTE_TYPE_LEAF_TABLE: u64 = 3;

/// G15 leaf PTE flag base (VALID | TYPE | AF | bit 55 — the M1 GPU-access bit), from
/// `AGXUnifiedAddressTranslator::encodePTEFlags` (0xfffffe0008ed82a0 in
/// the 14.8.3 kext). Of the M1 format, the permission tuple (AP [7:6],
/// PXN 53, UXN 54) carries over through the DPRR lookup; the memattr field
/// [4:2] does not (G15: AttrIndx 1 = uncached bit 2, AttrIndx 2 = device
/// bit 3, against the firmware's MAIR below).
const PTE_FLAGS_BASE: u64 = 0x80000000000403;
/// bit 11: set only in region 0 leaf entries
const PTE_FLAGS_REGION0: u64 = 1 << 11;
/// Attribute/protection bits that `reprot_pages` swaps: options [3:2],
/// DPRR attr [7:6] and protection bits 53/54.
const UAT_PROT_BITS: u64 = 0xC | 0xC0 | (1 << 53) | (1 << 54);

// The firmware's MAIR_EL1 is 0xFF004FF400FF (`rtk_start_anywhere_uatv2`
// and `__rtk_arm_start_bootstrap_area` in armfw_g15c): Attr0 0xFF Normal
// write-back, Attr1 0x00 Device-nGnRnE, Attr2 0xF4 Normal inner
// non-cacheable / outer write-back.

/// kUATMapFWUncached — options bit 2, AttrIndx 1: **Device-nGnRnE**. The
/// kext forces it on every map in its register-window range (eGART range
/// 9); see `Prot::options`.
const OPT_UNCACHED: u32 = 1 << 2;
/// kUATMapFWDeviceMem — options bit 3, AttrIndx 2: despite the name,
/// Normal memory, inner non-cacheable, outer write-back: the firmware's
/// view of the kext's block-2 buffers (`PROT_FW_NC_RW`).
const OPT_DEVICE: u32 = 1 << 3;

/// The kext's `kUATValidOptionsMask` assert (`TST W2, #0xFFFFFCF0`):
/// options bits [3:0] and [9:8] — perm [1:0], uncached 2, device 3, class
/// [9:8]. Anything else panics.
const OPT_VALID_MASK: u32 = 0x30F;

/// `kDPRRIndexLookup`, **u32 × 16** at 0xfffffe000710e2e4 in the 14.8.3
/// kext (`LDR W8,[X9,W8,UXTW#2]`), index = perm << 2 | class. The value v
/// is the M1 permission tuple: v[3:2] = AP (PTE [7:6]), v[1] = UXN (bit
/// 54), v[0] = PXN (bit 53) — the same encodings as the `Prot` constants
/// below (0 = FW+GPU NA, 3 = FW+GPU RW, 4 = FW RO, 6 = FW RW, 7 = FW RW +
/// GPU RO, …). The kext maps its kernel window with perm 3 (RW) or 1 (RO)
/// and class 0/1/3; everything else gets perm 0 (v = 0, no access — the
/// boot #29 firmware permission fault).
const DPRR_LOOKUP: [u8; 16] = [0, 0, 0, 0, 4, 1, 0, 0, 5, 0, 2, 0, 6, 7, 0, 3];

/// The flag half of `AGXUnifiedAddressTranslator::encodePTEFlags(ttbrIdx,
/// options)` — base | region bit | v3 bits | options bits [3:2]. The
/// caller ORs in the PA [41:14].
const fn encode_pte_flags(region: u32, options: u32) -> u64 {
    assert!(region < 2);
    assert!(options & !OPT_VALID_MASK == 0);
    let v3 = DPRR_LOOKUP[(((options & 3) << 2) | ((options >> 8) & 3)) as usize] as u64;
    PTE_FLAGS_BASE
        | (if region == 0 { PTE_FLAGS_REGION0 } else { 0 })
        | ((v3 << 4) & 0xC0)
        | (if v3 & 1 != 0 { 1 << 53 } else { 0 })
        | (if v3 & 2 != 0 { 1 << 54 } else { 0 })
        | if options & OPT_UNCACHED != 0 {
            4
        } else {
            (options & OPT_DEVICE) as u64
        }
}

const MEMATTR_CACHED: u8 = 0;
const MEMATTR_DEV: u8 = 1;
const MEMATTR_UNCACHED: u8 = 2;
/// G15: Normal, inner non-cacheable, outer write-back for the firmware
/// (AttrIndx 2, `kUATMapFWDeviceMem`): the kext's block-2 buffers.
const MEMATTR_FW_NC: u8 = 3;

const AP_FW_GPU: u8 = 0;
const AP_FW: u8 = 1;
const AP_GPU: u8 = 2;

/// The M1 permission tuple's high bits (PXN → PTE bit 53, UXN → bit 54;
/// GPU access is bit 55, always set in the G15 base). G15 reaches the same
/// encodings through the kext's DPRR lookup (`Prot::options`).
const HIGH_BITS_PXN: u16 = 1 << 1;
const HIGH_BITS_UXN: u16 = 1 << 2;
const HIGH_BITS_GPU_ACCESS: u16 = 1 << 3;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Prot {
    memattr: u8,
    ap: u8,
    high_bits: u16,
}

// Firmware + GPU access
const PROT_FW_GPU_NA: Prot = Prot::from_bits(AP_FW_GPU, 0, 0);
const _PROT_FW_GPU_RO: Prot = Prot::from_bits(AP_FW_GPU, 0, 1);
const _PROT_FW_GPU_WO: Prot = Prot::from_bits(AP_FW_GPU, 1, 0);
const PROT_FW_GPU_RW: Prot = Prot::from_bits(AP_FW_GPU, 1, 1);

// Firmware only access
const PROT_FW_RO: Prot = Prot::from_bits(AP_FW, 0, 0);
const _PROT_FW_NA: Prot = Prot::from_bits(AP_FW, 0, 1);
const PROT_FW_RW: Prot = Prot::from_bits(AP_FW, 1, 0);
const PROT_FW_RW_GPU_RO: Prot = Prot::from_bits(AP_FW, 1, 1);

// GPU only access
const PROT_GPU_RO: Prot = Prot::from_bits(AP_GPU, 0, 0);
const PROT_GPU_WO: Prot = Prot::from_bits(AP_GPU, 0, 1);
const PROT_GPU_RW: Prot = Prot::from_bits(AP_GPU, 1, 0);
const _PROT_GPU_NA: Prot = Prot::from_bits(AP_GPU, 1, 1);

pub(crate) mod prot {
    pub(crate) use super::Prot;
    use super::*;

    /// Firmware MMIO R/W
    pub(crate) const PROT_FW_MMIO_RW: Prot = PROT_FW_RW.memattr(MEMATTR_DEV);
    /// Firmware MMIO R/O
    pub(crate) const PROT_FW_MMIO_RO: Prot = PROT_FW_RO.memattr(MEMATTR_DEV);
    /// Firmware shared (uncached) RW
    pub(crate) const PROT_FW_SHARED_RW: Prot = PROT_FW_RW.memattr(MEMATTR_UNCACHED);
    /// Firmware shared (uncached) RO
    pub(crate) const PROT_FW_SHARED_RO: Prot = PROT_FW_RO.memattr(MEMATTR_UNCACHED);
    /// Firmware private (cached) RW
    pub(crate) const PROT_FW_PRIV_RW: Prot = PROT_FW_RW.memattr(MEMATTR_CACHED);
    /// Firmware RW, Normal non-cacheable for the firmware (G15: the kext's
    /// block 2 — the event page, the firmware-to-host rings, the control
    /// blocks — and the power block; spec: faults.md, "The fork's hang")
    pub(crate) const PROT_FW_NC_RW: Prot = PROT_FW_RW.memattr(MEMATTR_FW_NC);
    /// Firmware/GPU shared (uncached) RW
    pub(crate) const PROT_GPU_FW_SHARED_RW: Prot = PROT_FW_GPU_RW.memattr(MEMATTR_UNCACHED);
    /// Firmware/GPU shared (private) RW
    pub(crate) const PROT_GPU_FW_PRIV_RW: Prot = PROT_FW_GPU_RW.memattr(MEMATTR_CACHED);
    /// Firmware-RW/GPU-RO shared (private) RW
    pub(crate) const PROT_GPU_RO_FW_PRIV_RW: Prot = PROT_FW_RW_GPU_RO.memattr(MEMATTR_CACHED);
    /// GPU shared/coherent RW
    pub(crate) const PROT_GPU_SHARED_RW: Prot = PROT_GPU_RW.memattr(MEMATTR_UNCACHED);
    /// GPU shared/coherent RO
    pub(crate) const PROT_GPU_SHARED_RO: Prot = PROT_GPU_RO.memattr(MEMATTR_UNCACHED);
    /// GPU shared/coherent WO
    pub(crate) const PROT_GPU_SHARED_WO: Prot = PROT_GPU_WO.memattr(MEMATTR_UNCACHED);
}

impl Prot {
    const fn from_bits(ap: u8, uxn: u16, pxn: u16) -> Self {
        assert!(uxn <= 1);
        assert!(pxn <= 1);
        assert!(ap <= 3);

        Prot {
            high_bits: HIGH_BITS_GPU_ACCESS | (pxn * HIGH_BITS_PXN) | (uxn * HIGH_BITS_UXN),
            memattr: 0,
            ap,
        }
    }

    const fn memattr(&self, memattr: u8) -> Self {
        Self { memattr, ..*self }
    }

    /// The kext's DPRR index (perm << 2 | class) for this protection: the
    /// table entry whose value is the M1 tuple (AP, UXN, PXN). The table
    /// has no GPU-only (`AP_GPU`) tuple: those map as their FW+GPU twins
    /// (GPU RO → v 1, WO → v 2, RW → v 3) — with the perm-0 form a user
    /// buffer was NoAccess to the GPU (boot #103: the CDM stream fetch,
    /// fault info 0x4c03a019).
    const fn dprr_index(&self) -> u32 {
        let uxn = (self.high_bits & HIGH_BITS_UXN != 0) as u8;
        let pxn = (self.high_bits & HIGH_BITS_PXN != 0) as u8;
        let v = if self.ap == AP_GPU {
            // AP_GPU: (0,0) RO, (0,1) WO, (1,0) RW, (1,1) NA.
            match (uxn, pxn) {
                (0, 0) => 1,
                (0, 1) => 2,
                (1, 0) => 3,
                _ => 0,
            }
        } else {
            (self.ap << 2) | (uxn << 1) | pxn
        };
        if v == 0 {
            return 0;
        }
        let mut i = 0;
        while i < DPRR_LOOKUP.len() {
            if DPRR_LOOKUP[i] == v {
                return i as u32;
            }
            i += 1;
        }
        panic!("Prot has no G15 DPRR encoding");
    }

    /// The G15 options word (see `encode_pte_flags`): perm [1:0] and class
    /// [9:8] from the DPRR index, plus the memory attribute, as
    /// `AGXSecureGart::map` builds it: the uncached bit (4, Device-nGnRnE)
    /// for every map inside its register-window range, the 20 MB at
    /// 0xffff_fc20_1000_0000 (`(VA + 0x3DFF0000000) >> 22 < 5`, eGART
    /// range 9, where `createFWGPUMapping(…, 9)` puts the windows) — it
    /// replaces the device bit (8) there; everything else is cached. So
    /// MMIO maps get the uncached bit, and the M1 "uncached" (shared)
    /// protections map cached here; the firmware does its own cache
    /// maintenance on the host-written rings (DC CIVAC). The device bit
    /// is a cacheable type (Attr2): the firmware's AIC and PTD accesses
    /// through it went out as cache-line transactions and took SErrors
    /// (boots #46/#47).
    const fn options(&self) -> u32 {
        let idx = self.dprr_index();
        let mem = match self.memattr {
            MEMATTR_DEV => OPT_UNCACHED,
            MEMATTR_FW_NC => OPT_DEVICE,
            _ => 0,
        };
        (idx >> 2) | ((idx & 3) << 8) | mem
    }

    /// The G15 leaf PTE flag bits without the PA (the caller ORs it in).
    /// The region bit is stripped here; `map_pages`/`reprot_pages` add the
    /// entry's own region via `encode_pte_flags`.
    #[cfg(CONFIG_DEV_COREDUMP)]
    const fn as_pte(&self) -> u64 {
        encode_pte_flags(0, self.options()) & !PTE_FLAGS_REGION0
    }

    pub(crate) const fn is_cached_noncoherent(&self) -> bool {
        self.ap != AP_GPU && self.memattr == MEMATTR_CACHED
    }

    pub(crate) const fn as_uncached(&self) -> Self {
        self.memattr(MEMATTR_UNCACHED)
    }
}

impl Default for Prot {
    fn default() -> Self {
        PROT_FW_GPU_NA
    }
}

pub(crate) struct UatPageTable {
    ttb: PhysicalAddr,
    ttb_owned: bool,
    va_range: Range<u64>,
    oas_mask: u64,
}

impl UatPageTable {
    pub(crate) fn new(oas: u32) -> Result<Self> {
        mod_pr_debug!("UATPageTable::new: oas={}\n", oas);
        let ttb_page = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;
        let ttb = Page::into_phys(ttb_page);
        Ok(UatPageTable {
            ttb,
            ttb_owned: true,
            va_range: 0..(1u64 << UAT_IAS),
            oas_mask: (1u64 << oas) - 1,
        })
    }

    pub(crate) fn new_with_ttb(ttb: PhysicalAddr, va_range: Range<u64>, oas: u32) -> Result<Self> {
        mod_pr_debug!(
            "UATPageTable::new_with_ttb: ttb={:#x} range={:#x?} oas={}\n",
            ttb,
            va_range,
            oas
        );
        if ttb & (UAT_PGMSK as PhysicalAddr) != 0 {
            return Err(EINVAL);
        }
        if (va_range.start | va_range.end) & (UAT_PGMSK as u64) != 0 {
            return Err(EINVAL);
        }
        // SAFETY: The TTB is should remain valid (if properly mapped), as it is bootloader-managed.
        let ttb_page = match unsafe { Page::borrow_phys(&ttb) } {
            Some(page) => page,
            None => {
                pr_err!(
                    "UatPageTable::new_with_ttb: ttb at {:#x} is not mapped (DT using no-map?)\n",
                    ttb
                );
                return Err(EIO);
            }
        };
        // G15: the firmware builds its boot root table in this page when it
        // starts (the patchbay's `PTPB`), before the handoff, with its MMU
        // off: its stores may not reach this CPU's caches. Zeroing the page
        // here raced the firmware's boot and left it dead (2026-10-17); the
        // clean slate is made before the firmware starts instead
        // (`Uat::prepare_regions`). Drop the CPU's lines so the walk below
        // reads what the firmware wrote.
        ttb_page.with_page_mapped(|ptr| crate::mem::dc_civac(ptr as *const u8, UAT_PGSZ));

        Ok(UatPageTable {
            ttb,
            ttb_owned: false,
            va_range,
            oas_mask: (1u64 << oas) - 1,
        })
    }

    pub(crate) fn ttb(&self) -> PhysicalAddr {
        self.ttb
    }

    /// Which G15 UAT region this table's VAs live in (bit 42). The walk is
    /// region-relative (the IAS mask strips bit 42, which is exactly the
    /// region select); the region picks the GPTBAT base (ttb0/ttb1) and
    /// the leaf entries' bit 11.
    fn region(&self) -> u32 {
        ((self.va_range.start >> UAT_IAS) & 1) as u32
    }

    fn with_pages<F>(
        &mut self,
        iova_range: Range<u64>,
        alloc: bool,
        free: bool,
        mut cb: F,
    ) -> Result
    where
        F: FnMut(u64, &[Pte]) -> Result,
    {
        mod_pr_debug!(
            "UATPageTable::with_pages: {:#x?} alloc={} free={}\n",
            iova_range,
            alloc,
            free
        );
        if (iova_range.start | iova_range.end) & (UAT_PGMSK as u64) != 0 {
            pr_err!(
                "UATPageTable::with_pages: iova range not aligned: {:#x?}\n",
                iova_range
            );
            return Err(EINVAL);
        }

        if iova_range.is_empty() {
            return Ok(());
        }

        let mut iova = iova_range.start & UAT_IASMSK;
        let mut last_iova = iova;
        // Handle the case where iova_range.end is just at the top boundary of the IAS
        let end = ((iova_range.end - 1) & UAT_IASMSK) + 1;

        let mut pt_addr: [Option<PhysicalAddr>; UAT_LEVELS] = Default::default();
        pt_addr[UAT_LEVELS - 1] = Some(self.ttb);

        'outer: while iova < end {
            mod_pr_debug!("UATPageTable::with_pages: iova={:#x}\n", iova);
            let addr_diff = last_iova ^ iova;
            for level in (0..UAT_LEVELS - 1).rev() {
                // If the iova has changed at this level or above, invalidate the physaddr
                if addr_diff & !((1 << (UAT_PGBIT + (level + 1) * UAT_LVBIT)) - 1) != 0 {
                    if let Some(phys) = pt_addr[level].take() {
                        if free {
                            mod_pr_debug!(
                                "UATPageTable::with_pages: free level {} {:#x?}\n",
                                level,
                                phys
                            );
                            // SAFETY: Page tables for our VA ranges always come from Page::into_phys().
                            unsafe { Page::from_phys(phys) };
                        }
                        mod_pr_debug!("UATPageTable::with_pages: invalidate level {}\n", level);
                    }
                }
            }
            last_iova = iova;
            for level in (0..UAT_LEVELS - 1).rev() {
                // Fetch the page table base address for this level
                if pt_addr[level].is_none() {
                    let phys = pt_addr[level + 1].unwrap();
                    mod_pr_debug!(
                        "UATPageTable::with_pages: need level {}, parent phys {:#x}\n",
                        level,
                        phys
                    );
                    let upidx = ((iova >> (UAT_PGBIT + (level + 1) * UAT_LVBIT) as u64) & UAT_LVMSK)
                        as usize;
                    // SAFETY: Page table addresses are either allocated by us, or
                    // firmware-managed and safe to borrow a struct page from.
                    let upt = unsafe { Page::borrow_phys_unchecked(&phys) };
                    mod_pr_debug!("UATPageTable::with_pages: borrowed phys {:#x}\n", phys);
                    pt_addr[level] =
                        upt.with_pointer_into_page(upidx * PTE_SIZE, PTE_SIZE, |p| {
                            let uptep = p as *const _ as *const Pte;
                            // SAFETY: with_pointer_into_page() ensures the pointer is valid,
                            // and our index is aligned so it is safe to deref as an AtomicU64.
                            let upte = unsafe { &*uptep };
                            let mut upte_val = upte.load(Ordering::Relaxed);
                            // Allocate if requested
                            if upte_val == 0 && alloc {
                                let pt_page = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;
                                mod_pr_debug!("UATPageTable::with_pages: alloc PT at {:#x}\n", pt_page.phys());
                                let pt_paddr = Page::into_phys(pt_page);
                                upte_val = pt_paddr | PTE_TYPE_LEAF_TABLE;
                                upte.store(upte_val, Ordering::Relaxed);
                            }
                            if upte_val & PTE_TYPE_BITS == PTE_TYPE_LEAF_TABLE {
                                Ok(Some(upte_val & self.oas_mask & (!UAT_PGMSK as u64)))
                            } else if upte_val == 0 || (!alloc && !free) {
                                mod_pr_debug!("UATPageTable::with_pages: no level {}\n", level);
                                Ok(None)
                            } else {
                                pr_err!("UATPageTable::with_pages: Unexpected Table PTE value {:#x} at iova {:#x} index {} phys {:#x}\n", upte_val,
                                        iova, level + 1, phys + ((upidx * PTE_SIZE) as PhysicalAddr));
                                Ok(None)
                            }
                        })?;
                    mod_pr_debug!(
                        "UATPageTable::with_pages: level {} PT {:#x?}\n",
                        level,
                        pt_addr[level]
                    );
                }
                // If we don't have a page table, skip this entire level
                if pt_addr[level].is_none() {
                    let block = 1 << (UAT_PGBIT + UAT_LVBIT * (level + 1));
                    let old = iova;
                    iova = align(iova + 1, block);
                    mod_pr_debug!(
                        "UATPageTable::with_pages: skip {:#x} {:#x} -> {:#x}\n",
                        block,
                        old,
                        iova
                    );
                    continue 'outer;
                }
            }

            let idx = ((iova >> UAT_PGBIT as u64) & UAT_LVMSK) as usize;
            let max_count = UAT_NPTE - idx;
            let count = (((end - iova) >> UAT_PGBIT) as usize).min(max_count);
            let phys = pt_addr[0].unwrap();
            mod_pr_debug!(
                "UATPageTable::with_pages: leaf PT at {:#x} idx {:#x} count {:#x} iova {:#x}\n",
                phys,
                idx,
                count,
                iova
            );
            // SAFETY: Page table addresses are either allocated by us, or
            // firmware-managed and safe to borrow a struct page from.
            let pt = unsafe { Page::borrow_phys_unchecked(&phys) };
            pt.with_pointer_into_page(idx * PTE_SIZE, count * PTE_SIZE, |p| {
                let ptep = p as *const _ as *const Pte;
                // SAFETY: We know this is a valid pointer to PTEs and the range is valid and
                // checked by with_pointer_into_page().
                let ptes = unsafe { core::slice::from_raw_parts(ptep, count) };
                cb(iova, ptes)?;
                Ok(())
            })?;

            let block = 1 << (UAT_PGBIT + UAT_LVBIT);
            iova = align(iova + 1, block);
        }

        if free {
            for level in (0..UAT_LEVELS - 1).rev() {
                if let Some(phys) = pt_addr[level] {
                    mod_pr_debug!(
                        "UATPageTable::with_pages: free level {} {:#x?}\n",
                        level,
                        phys
                    );
                    // SAFETY: Page tables for our VA ranges always come from Page::into_phys().
                    unsafe { Page::from_phys(phys) };
                }
            }
        }

        Ok(())
    }

    pub(crate) fn alloc_pages(&mut self, iova_range: Range<u64>) -> Result {
        mod_pr_debug!("UATPageTable::alloc_pages: {:#x?}\n", iova_range);
        self.with_pages(iova_range, true, false, |_, _| Ok(()))
    }

    pub(crate) fn map_pages(
        &mut self,
        iova_range: Range<u64>,
        mut phys: PhysicalAddr,
        prot: Prot,
        one_page: bool,
    ) -> Result {
        mod_pr_debug!(
            "UATPageTable::map_pages: {:#x?} {:#x?} {:?}\n",
            iova_range,
            phys,
            prot
        );
        if phys & (UAT_PGMSK as PhysicalAddr) != 0 {
            pr_err!("UATPageTable::map_pages: phys not aligned: {:#x?}\n", phys);
            return Err(EINVAL);
        }

        let flags = encode_pte_flags(self.region(), prot.options());

        self.with_pages(iova_range, true, false, |iova, ptes| {
            for (idx, pte) in ptes.iter().enumerate() {
                let ptev = pte.load(Ordering::Relaxed);
                if ptev != 0 {
                    pr_err!(
                        "UATPageTable::map_pages: Page at IOVA {:#x} is mapped (PTE: {:#x})\n",
                        iova + (idx * UAT_PGSZ) as u64,
                        ptev
                    );
                }
                pte.store(phys | flags, Ordering::Relaxed);
                if !one_page {
                    phys += UAT_PGSZ as PhysicalAddr;
                }
            }
            Ok(())
        })
    }

    pub(crate) fn reprot_pages(&mut self, iova_range: Range<u64>, prot: Prot) -> Result {
        mod_pr_debug!(
            "UATPageTable::reprot_pages: {:#x?} {:?}\n",
            iova_range,
            prot
        );
        let flags = encode_pte_flags(self.region(), prot.options());
        self.with_pages(iova_range, true, false, |iova, ptes| {
            for (idx, pte) in ptes.iter().enumerate() {
                let ptev = pte.load(Ordering::Relaxed);
                if ptev & PTE_TYPE_BITS != PTE_TYPE_LEAF_TABLE {
                    pr_err!(
                        "UATPageTable::reprot_pages: Page at IOVA {:#x} is unmapped (PTE: {:#x})\n",
                        iova + (idx * UAT_PGSZ) as u64,
                        ptev
                    );
                    continue;
                }
                pte.store((ptev & !UAT_PROT_BITS) | flags, Ordering::Relaxed);
            }
            Ok(())
        })
    }

    pub(crate) fn unmap_pages(&mut self, iova_range: Range<u64>) -> Result {
        mod_pr_debug!("UATPageTable::unmap_pages: {:#x?}\n", iova_range);
        self.with_pages(iova_range, false, false, |iova, ptes| {
            for (idx, pte) in ptes.iter().enumerate() {
                if pte.load(Ordering::Relaxed) & PTE_TYPE_LEAF_TABLE == 0 {
                    pr_err!(
                        "UATPageTable::unmap_pages: Page at IOVA {:#x} already unmapped\n",
                        iova + (idx * UAT_PGSZ) as u64
                    );
                }
                pte.store(0, Ordering::Relaxed);
            }
            Ok(())
        })
    }
}

impl Drop for UatPageTable {
    fn drop(&mut self) {
        mod_pr_debug!("UATPageTable::drop range: {:#x?}\n", &self.va_range);
        if self
            .with_pages(self.va_range.clone(), false, true, |iova, ptes| {
                for (idx, pte) in ptes.iter().enumerate() {
                    if pte.load(Ordering::Relaxed) != 0 {
                        pr_err!(
                            "UATPageTable::drop: Leaked page at IOVA {:#x}\n",
                            iova + (idx * UAT_PGSZ) as u64
                        );
                    }
                }
                Ok(())
            })
            .is_err()
        {
            pr_err!("UATPageTable::drop failed to free page tables\n",);
        }
        if self.ttb_owned {
            mod_pr_debug!("UATPageTable::drop: Free TTB {:#x}\n", self.ttb);
            // SAFETY: If we own the ttb, it was allocated with Page::into_phys().
            unsafe {
                Page::from_phys(self.ttb);
            }
        }
    }
}
