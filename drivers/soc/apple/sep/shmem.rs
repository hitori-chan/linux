// SPDX-License-Identifier: GPL-2.0-only
//
// The shared memory the warm registration hands the SEP, laid out as macOS 14.8.3's AppleSEPManager lays it out
// (rda AppleSEPManager; the registration was 0x1c000 bytes, sep-1.log 1458):
// - a table at 0 of 16-byte entries {u32 tag, u32 size, u64 offset}, ended by "llun" and 12 zero bytes, then each
//   channel at the next SEP page (0x4000) in the table's order, its size rounded up to the page, the rest zeroed
//   (AppleSEPSharedMemoryBuffer::createWithOwnerChannelsAndMapper 0xfffffe0009d17098);
// - the channels (_allocateShm 0xfffffe0009d1af40): CINP 0x8000, the SEP's panic text, left zeroed; GALF 0x1000,
//   the xART flags, {u32 0x20, then 0x20 (tag, value) pairs}, only 'xART' named, its value 1 only while NVRAM holds
//   oblit-inprogress, so 0 (_loadFlagData 0xfffffe0009d1adac); then the objects in __channel_objs' order, each its
//   u32 length and its bytes, its entry's size the length + 4 (_loadChannelObjectEntries 0xfffffe0009d1aa20,
//   _loadChannelObjectData 0xfffffe0009d1ac64): OPLA the LocalPolicy manifest and IPIS the iBoot manifest
//   (/chosen/boot-object-manifests, which sep-on.ko copies into node properties), TOCS 32 fixed bytes;
// - no trace channels: they come only with _allocateShm's second argument.
// The SEP faults later on a registration without the two manifests (TOUCHID.md), so none is built without them.

use kernel::device;
use kernel::dma;
use kernel::platform;
use kernel::prelude::*;

pub(crate) const SEP_PAGE: usize = 0x4000;
/// What the table, CINP, GALF, OPLA, IPIS and TOCS take on this Mac, as macOS's registration.
pub(crate) const SHMEM_SIZE: usize = 0x1_c000;
/// CINP, the channel the SEP writes its panic text into, for the summary: the first after the table's page.
pub(crate) const CINP_OFFSET: usize = SEP_PAGE;
pub(crate) const CINP_LEN: usize = 0x8000;

const GALF_LEN: usize = 0x1000;
const GALF_PAIRS: u32 = 0x20;
const TOCS: &[u8; 32] = b"This is my wonderful test data!\0";

pub(crate) type ShMem = dma::Coherent<[u8]>;

/// What a channel holds at its offset.
enum Fill<'a> {
    Zero,
    Flags,
    Object(&'a [u8]),
}

pub(crate) struct Built {
    pub(crate) buf: ShMem,
    pub(crate) opla_len: usize,
    pub(crate) ipis_len: usize,
}

const fn round_up(v: usize, to: usize) -> usize {
    v.div_ceil(to) * to
}

/// A manifest from its node property: one DER IM4M, SEQUENCE { IA5String "IM4M", ... }, filling the property.
fn manifest(dev: &device::Device, prop: &CStr) -> Result<KVec<u8>> {
    let node = dev.fwnode().ok_or(EIO)?;
    let n = node.property_count_elem::<u8>(prop).unwrap_or(0);
    let m = if n > 0 { node.property_read_array_vec::<u8>(prop, n)?.required_by(dev)? } else { KVec::new() };
    let body = match m.get(..2) {
        Some([0x30, 0x81]) => m.get(3..).filter(|b| b.len() == usize::from(m[2])),
        Some([0x30, 0x82]) => m.get(4..).filter(|b| b.len() == usize::from(u16::from_be_bytes([m[2], m[3]]))),
        _ => None,
    };
    if !body.is_some_and(|b| b.starts_with(b"\x16\x04IM4M")) {
        dev_err!(dev, "[sep2] not attaching: '{}' is missing or not one IM4M ({} bytes); the SEP needs both manifests\n", prop, n);
        return Err(EINVAL);
    }
    Ok(m)
}

/// The buffer, zeroed and filled before the SEP learns its address; probe is its only writer.
pub(crate) fn build(pdev: &platform::Device<device::Core<'_>>) -> Result<Built> {
    let dev: &device::Device<device::Core<'_>> = pdev.as_ref();
    let opla = manifest(dev, c"local-policy-manifest")?;
    let ipis = manifest(dev, c"iboot-manifest")?;

    let channels: [(&[u8; 4], usize, Fill<'_>); 5] = [
        (b"CINP", CINP_LEN, Fill::Zero),
        (b"GALF", GALF_LEN, Fill::Flags),
        (b"OPLA", 4 + opla.len(), Fill::Object(&opla)),
        (b"IPIS", 4 + ipis.len(), Fill::Object(&ipis)),
        (b"TOCS", 4 + TOCS.len(), Fill::Object(TOCS)),
    ];
    // the table's page, then the channels, page by page
    let mut at = [0usize; 5];
    let mut end = round_up(16 * (channels.len() + 1), SEP_PAGE);
    for (i, (_, size, _)) in channels.iter().enumerate() {
        at[i] = end;
        end += round_up(*size, SEP_PAGE);
    }
    if end != SHMEM_SIZE {
        dev_err!(dev, "[sep2] not attaching: the channels take {:#x} bytes, macOS's {:#x} (OPLA {:#x}, IPIS {:#x})\n",
            end, SHMEM_SIZE, opla.len(), ipis.len());
        return Err(EINVAL);
    }

    let buf = dma::Coherent::<u8>::zeroed_slice(dev, SHMEM_SIZE, GFP_KERNEL)?;
    // SAFETY: the SEP has not been given the buffer yet, and nothing else holds it.
    let b = unsafe { buf.as_mut() };
    // the channels' contents first, the table last: a failure leaves no table that looks whole
    for (i, (_, _, fill)) in channels.iter().enumerate() {
        let o = at[i];
        match fill {
            Fill::Zero => {}
            Fill::Flags => {
                b[o..o + 4].copy_from_slice(&GALF_PAIRS.to_le_bytes());
                b[o + 4..o + 8].copy_from_slice(&u32::from_be_bytes(*b"xART").to_le_bytes());
            }
            Fill::Object(d) => {
                b[o..o + 4].copy_from_slice(&(d.len() as u32).to_le_bytes());
                b[o + 4..o + 4 + d.len()].copy_from_slice(d);
            }
        }
    }
    for (i, (tag, size, _)) in channels.iter().enumerate() {
        let e = 16 * i;
        b[e..e + 4].copy_from_slice(*tag);
        b[e + 4..e + 8].copy_from_slice(&(round_up(*size, SEP_PAGE) as u32).to_le_bytes());
        b[e + 8..e + 16].copy_from_slice(&(at[i] as u64).to_le_bytes());
    }
    let t = 16 * channels.len();
    b[t..t + 4].copy_from_slice(b"llun");

    Ok(Built { buf, opla_len: opla.len(), ipis_len: ipis.len() })
}
