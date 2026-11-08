// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) The Asahi Linux Contributors
#![recursion_limit = "2048"]

//! Apple SEP: the lab's Touch ID stages on the M3 Max (t6034), a test driver.
//!
//! Asahi's sep.rs (the platform driver, the mailbox, the DMA buffers) with macOS's warm path in place of its cold
//! boot: iBoot boots the sepOS before m1n1, and macOS's AppleSEPManager then only registers its shared memory and
//! enables the apps, which each stage below follows in macOS's order (docs/hardware/TOUCHID.md, SEP-PROTOCOLS.md).
//!
//! iBoot boots the sepOS (`/chosen/sepfw-load-at-boot`); the lab module `sep-on.ko` adds the SEP's DART,
//! mailbox and this node (`apple,t6031-sep`) with the boot manifests and the stage, `apple,sep2-stage`:
//! - 0 (absent): register the shared memory (endpoint 0xFE), log the discovery, send nothing more (step 1);
//! - 1: then enable `hdcp` and `xarm` and ask the security mode, as macOS does (proto::STAGE1);
//! - 2: then enable `stac` (proto::STAGE2);
//! - 3: macOS's next messages in its order: `hdcp`'s interface count and launches between the two enables,
//!   `stac`'s power-on after them, then the xART service opens on the `.gl` copy the firmware loader hands probe
//!   (`apple-sep-xart.gl`, read-only, sep/xart.rs): the held op 0x0e is answered with protected-data-access, op
//!   0x13 with the OS UUID (both node properties from sep-on.ko; the UUID is never logged), the root reads (op 0)
//!   with their records, an app's name (op 0x1d) with status 0x16, as macOS. The service stops at the first
//!   session read (op 0x05), a write or an op 14.8.3 did not make before it: that request and all after it are
//!   held, not answered.
//! - 4: then the session reads (op 0x05, a locker each): the UUID from xarm's out buffer, the record (type 4, the
//!   SEP's, or 3) at 0 of its in buffer, or status 0 with nothing, as macOS's case 5. The service stops at the
//!   first write (op 0x06 or 0x07) or an op 14.8.3 did not make.
//! - 5: then the writes, into the `.gl` copy in memory and never to a disk (sep/xart.rs): a root record (op
//!   0x01), a locker (op 0x06) and a locker's delete (op 0x07), each answered as macOS's cases 1, 6 and 7. The
//!   service stops at the first request that is neither a served read nor a served write, and at a write macOS
//!   would panic on or refuse (a CRC-16 that fails, a length outside its range, an empty record, no free slot).
//!   A served root or locker write would leave the disk behind the SEP after a reboot: below stage 7 op 0x01 and
//!   op 0x06 stop the service, and so does a delete that finds its record.
//! - 6: then the key store (sep/sks.rs): once the discovery names `sks ` at endpoint 0x12 (sizes 0x02010201, as
//!   14.8.3's), its two 0x8000-byte buffers are registered in macOS's order (proto::STAGE6) and the key store's
//!   fixed start-up goes out, one request at a time, each waiting up to 6 s for its reply: get_capabilities with a
//!   v1 header (status 0, 0x5c bytes; the header version becomes min(2, the SEP's)), set_env {1,
//!   cpx-encryption-mode, 4, 0x400 zeros} (status 0, 0x58 bytes) and null_d_key (status -1, as on macOS with
//!   no-effaceable-storage). Anything else, a timeout or the xART service stopping ends it. The key store's own
//!   messages are logged, never answered; xART requests are served as at stage 5.
//! - 7: then Linux's identity key bag, kept by the host (27.2's SEP keeps none with options 0), in 27.2's dialect
//!   (sep/sks.rs): with no kept bag, create (v5), copy_keybag_uuid, copy_keybag (the wrapped bag, shown at debugfs
//!   `apple-sep/identity.kb` for the run to keep), unload; then load the wrapped bag, make_system_keybag (v1) for the
//!   session of the identity file's uid, unload, and device_state_transition to unlocked, one request at a time,
//!   each ending the step on another answer. The UUID, the secret and the uid come from `apple-sep-identity.bin`,
//!   a kept bag from `apple-sep-identity.kb`, through the firmware loader; the UUID and the secret are never
//!   logged. An xART root or locker write is logged (op, owner, length, CRC-16, whether its key holds a
//!   record) and held, never answered: an answer would let the SEP count a write no disk has
//!   (TOUCHID.md), so the request that caused it times out and the step ends there.
//! - 8: then, with the session unlocked, `scrd` (0x0a) and `sbio` (0x08) are enabled as 14.8.3 enables them
//!   (proto::STAGE8, 0x4000 each way) and SBIO's queries that need no sensor go out over the generic transfer, one
//!   single-packet transaction at a time, each waiting up to 10 s as macOS's: 0x73 {8} (27.2's communication init;
//!   any other answer ends the step), then 0x7c, 0x40, 0x6b, 0x79, 0x7a (its count only), 0x38 v2, 0x39, 0x33 for
//!   -1, 501 and the uid (each ID only compared with the `.gl` copy's lockers), 0x2b, 0x2e, 0x36, 0x63 and 0x1f,
//!   their statuses and replies logged; last, `scrd`'s INITIALIZE in 27.2's framing (request 4, 0x24 bytes), up to
//!   5 s, and the session's state again. SBIO's own messages are logged, never answered. No sensor op (0x80, 0x17
//!   and on), no context (0x2d), no catacomb load or save, no 0x48.
//! - 9: then the sensor's bring-up through SBIO, relayed over `sensor.c` (run_mesa), the sensor off after.
//! - 10: then the credential an enrolment's BEGIN_ENROL carries (Touch ID step 10b), as 27.2 makes it: an ACM context
//!   in `scrd` (ContextCreateWithTracking for the identity file's uid, ExternalizeContext), the kept bag's secret
//!   verified into it by the key store (load the wrapped bag, verify_secret v1, unload: AppleKeyStore::identity_verify),
//!   the policy "TouchIdEnrollment" checked in it, then the context deleted. Any status but 0 ends it, the context
//!   deleted; no enrolment is begun. xART writes are held as at stage 7.
//! - 11: as 10, and between stage 9's bring-up and its power-off one capture with the sensor alone (Touch ID step 10a):
//!   StartCapture, the status polled for up to 120 s while a finger is placed, one image read and its slices checked,
//!   Idle. Nothing goes to the SEP for it; the image is never logged, kept or relayed.
//! - 12: as 9, then between the bring-up and the power-off an enrolment cancelled before its save (Touch ID step
//!   10c, run_enrol): the system context (0x2d −1), the components' states (0x6b), the user's context (0x2d, 0x2b),
//!   the credential of stage 10 kept open, BEGIN_ENROL 0x03, then per image a capture as stage 11's, relayed as
//!   27.2 relays it (0x23, 0x06, 0x65 in two packets, 0x07, 0x08 for an image the SEP takes, 0x22) until 0x08's
//!   done flag or the first refusal; then the cancel 0x05 and the credential closed. No save (0x6c, 0x37, 0x70);
//!   an xART write request is held as at stage 7 and ends the step. The images are zeroed after their relay.
//!
//! Every message sent and received is logged with the prefix `[sep2]`. What may be sent is fixed by
//! proto::allowed, checked in `SepData::send`, the only way to the mailbox: the registration once per boot,
//! and the control endpoint's out-of-line size and address ops for those three apps and the security-mode
//! request; at stage 3 also hdcp's two ops, stac's power-on and the xART replies. Below stage 3 no message answers
//! the SEP: the xART service's requests (endpoint 0x13) are logged and held, as macOS holds them until its
//! gigalocker is open. A root or locker write is refused at every stage (logged, never serviced, never answered),
//! and so is a locker delete that finds its record; one that finds none is answered from stage 5. At stage 6 also
//! sks's size and address ops and the key store's three start-up requests, at stage 7 the identity's eight commands, at stage 8 scrd's and sbio's enables, stage 8's
//! SBIO queries and scrd's INITIALIZE. The module has no APFS or block-device code, no sensor, GPIO or SPI code, and no
//! boot, reset or power message.

mod ctl;
mod mesa;
mod proto;
mod inbox;
mod shmem;
mod sks;
mod xarm;
mod xart;

use core::fmt::Write as _;
use kernel::{
    bindings,
    debugfs,
    device,
    dma,
    dma::Device as _,
    firmware::Firmware,
    module_platform_driver,
    new_condvar,
    new_mutex,
    of,
    platform,
    prelude::*,
    soc::apple::mailbox::{
        MailCallback,
        Mailbox,
        Message, //
    },
    sync::{
        aref::ARef,
        barrier,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        CondVar,
        CondVarTimeoutResult,
        Mutex, //
    },
    time,
    types::ForeignOwnable,
    workqueue::{
        self,
        impl_has_work,
        new_work,
        Work,
        WorkItem, //
    }, //
};

use proto::{App, Data, Step};
use shmem::ShMem;

/// The node property sep-on.ko sets from its `stage` parameter.
const STAGE_PROP: &CStr = c"apple,sep2-stage";
const STAGE_MAX: u32 = 12;

/// Stage 3: the `.gl` copy, by the firmware loader (the run sets its path to a tmpfs directory).
const XART_FW: &CStr = c"apple-sep-xart.gl";
/// Stage 7: the identity, 52 bytes: its UUID (16), its secret (32) and the uid whose session it unlocks (u32 LE).
const IDENTITY_FW: &CStr = c"apple-sep-identity.bin";
/// Stage 7: the wrapped identity bag a previous run's copy_keybag returned (absent: the run creates one).
const IDENTITY_BAG_FW: &CStr = c"apple-sep-identity.kb";
/// sep-on.ko's stage-3 properties: the OS UUID's 16 bytes (absent: none) and protected-data-access.
const OS_UUID_PROP: &CStr = c"apple,os-uuid";
const PDA_PROP: &CStr = c"apple,protected-data-access";
/// Stage 6: sep-on.ko's copy of the ADT's /defaults/cpx-encryption-mode (0 when the ADT lacks it, as set_env reads
/// it), which set_env sends.
const CPX_PROP: &CStr = c"apple,cpx-encryption-mode";
/// Without the property (a sep-on.ko older than stage 6): this Mac's 27.0.1 ADT's value
/// (kexts/ipsw2701/adt_j514map_2701.bin; work/scratch/agents/sks.md, the 0x2a row).
const CPX_DEFAULT: u32 = 2;
/// Stage 6: how long after the xART service opens the discovery may take to name `sks ` (step 5 saw it within its
/// 15 s watch, after the xART reads).
const SKS_ANNOUNCE_MS: u32 = 15_000;
/// hdcp's and stac's replies, as the control endpoint's.
const APP_TIMEOUT_MS: u32 = 2000;
/// Stage 8: an SBIO transaction's wait (AppleSEPGenericTransfer::transact, 10 s) and scrd's (sendSEPCommand, 5 s).
const SBIO_TIMEOUT_MS: u32 = 10_000;
const SCRD_TIMEOUT_MS: u32 = 5000;
/// Stage 11: how long the capture waits for a finger (time for a person told to touch it) and how often it reads the
/// status (the interrupt is not wired).
const CAPTURE_MS: u32 = 120_000;
const CAPTURE_POLL_MS: u32 = 10;
/// Stage 12: the images an enrolment may take (the SEP says when it is complete; macOS has no count, another fork
/// stops at 12), the window for each (macOS's enrolment times out; 60 s here), and the pause after each for the finger
/// to lift and come back (each image its own touch: the touch's first, as after a finger detect).
const ENROL_IMAGES: u32 = 20;
const ENROL_CAPTURE_MS: u32 = 60_000;
const ENROL_LIFT_MS: u32 = 1_500;
/// xART requests held before the service opens (macOS: one, op 0x0e) or after it stops.
const HELD_MAX: usize = 16;

/// The SEP DART's window (the ADT's vm-base and vm-size, sep-on.c's `iommus`): every buffer handed to the SEP
/// must lie in it, and its address >> 12 must fit the message's 32-bit data.
const WINDOW_BASE: u64 = 0x100_0000_4000;
const WINDOW_END: u64 = WINDOW_BASE + 0x3ff0_0000;

/// Step 1 saw the first answer within 0.3 s.
const FIRST_RESPONSE_MS: u32 = 5000;
/// The discovery is over once nothing came for this long (macOS sent its first enable right after the
/// burst; sep-1.log 1527-1531).
const QUIET_MS: u32 = 300;
const SETTLE_MAX_MS: u32 = 10_000;
const POLL_MS: u32 = 50;
/// How long the driver watches after its last message before the summary.
const WATCH_MS: u32 = 15_000;

/// Every received message is logged up to this many, then every 256th.
const RX_LOG_MAX: u64 = 4096;

const MAX_APPS: usize = 32;

/// One registration per boot, as AppleSEPBooter sends one per reset. The driver is built in
/// (CONFIG_APPLE_SEP=y), so this outlives a node removed and added again.
static REGISTERED: Atomic<bool> = Atomic::new(false);

/// A 4CC carried big-endian in a message's data.
struct FourCc(u32);

impl kernel::fmt::Display for FourCc {
    fn fmt(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result {
        for b in self.0.to_be_bytes() {
            let c = if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' };
            f.write_char(c)?;
        }
        Ok(())
    }
}

/// Bytes in hex, space-separated, for the log.
struct Hex<'a>(&'a [u8]);

impl kernel::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result {
        let mut gap = "";
        for b in self.0 {
            write!(f, "{}{:02x}", gap, b)?;
            gap = " ";
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DiscApp {
    ep: u8,
    name: Option<u32>,
    sizes: Option<u32>,
}

impl DiscApp {
    const EMPTY: DiscApp = DiscApp {
        ep: 0,
        name: None,
        sizes: None,
    };
}

struct State {
    ctl: ctl::Slot,
    rx_total: u64,
    apps: [DiscApp; MAX_APPS],
    n_apps: usize,
    /// The endpoint (hdcp's, stac's) whose next message the bring-up waits for, and that message.
    app_wait: Option<u8>,
    app_reply: Option<Message>,
    /// Stage 3: the xART service answers requests (`SepData::serve_xarm`) from when the bring-up opens it until
    /// it stops; before and after, they are held here.
    serving: bool,
    stopped: Option<&'static str>,
    held: [Option<Message>; HELD_MAX],
    n_held: usize,
    held_lost: u32,
    /// Stage 6: the key store's request in flight (its command and sequence number), its reply, and the counts.
    sks_wait: Option<(u8, u8)>,
    sks_reply: Option<Message>,
    sks: SksCounts,
    /// Stage 8's SBIO and scrd traffic.
    sbio: SbioCounts,
}

/// Stage 8's traffic, for the summary.
#[derive(Clone, Copy, Default)]
struct SbioCounts {
    sent: u32,
    replies: u32,
    /// Error packets (marker 0xFF) and replies with a nonzero status.
    refused: u32,
    /// The SEP's own messages on sbio (marker below 0xFC) and scrd's for no request, never answered.
    sep_msgs: u32,
    outcome: Option<&'static str>,
    scrd: Option<&'static str>,
    /// Stage 9: how the sensor's part ended.
    mesa: Option<&'static str>,
    /// Stage 10: the last scrd request ID (INITIALIZE's is 1) and how the credential ended.
    scrd_id: u32,
    cred: Option<&'static str>,
    /// Stage 11: how the capture ended.
    capture: Option<&'static str>,
    /// Stage 12: how the enrolment ended.
    enrol: Option<&'static str>,
}

/// Stage 6's key store traffic, for the summary.
#[derive(Clone, Copy)]
struct SksCounts {
    sent: u32,
    replies: u32,
    /// Replies for no request in flight (late, or not ours).
    stray: u32,
    /// The SEP's own messages (byte 1 below 0x80), never answered.
    sep_msgs: u32,
    /// Reply images whose digest __payload_hash accepts or refuses (a refusal is logged only).
    digest_good: u32,
    digest_bad: u32,
    /// How the start-up ended; None before it began.
    outcome: Option<&'static str>,
    /// The negotiated header version, once the start-up has it.
    version: u32,
    /// Stage 7: how the identity's sequence ended; None before it began.
    identity: Option<&'static str>,
    /// The sequence number the key store's next request takes.
    next_seq: u8,
}

impl State {
    fn hold(&mut self, msg: Message) {
        if self.n_held < HELD_MAX {
            self.held[self.n_held] = Some(msg);
            self.n_held += 1;
        } else {
            self.held_lost += 1;
        }
    }
}

impl State {
    fn app(&mut self, ep: u8) -> Option<&mut DiscApp> {
        if let Some(i) = self.apps[..self.n_apps].iter().position(|a| a.ep == ep) {
            return Some(&mut self.apps[i]);
        }
        if self.n_apps == MAX_APPS {
            return None;
        }
        self.apps[self.n_apps] = DiscApp { ep, ..DiscApp::EMPTY };
        self.n_apps += 1;
        Some(&mut self.apps[self.n_apps - 1])
    }

    fn find(&self, ep: u8) -> Option<DiscApp> {
        self.apps[..self.n_apps].iter().find(|a| a.ep == ep).copied()
    }
}

/// What came of one relayed image (stage 12): go on (the image used for the enrolment or not), or stop, and why.
enum Relay {
    Next(bool),
    Done(&'static str),
}

/// An SBIO transaction's answer: its status (an error packet's, or u32::MAX for one with status 0) and its data.
struct SbioReply {
    status: u32,
    data: KVec<u8>,
}

/// An app's out-of-line pair: `inbound` the SEP reads (ops 0x04, 0x02), `outbound` it writes (0x05, 0x03).
struct OolPair {
    inbound: ShMem,
    outbound: ShMem,
}

struct Bufs {
    shmem: Option<ShMem>,
    ool: [Option<OolPair>; 6],
}

fn app_index(app: App) -> Option<usize> {
    match app {
        App::Hdcp => Some(0),
        App::Xarm => Some(1),
        App::Stac => Some(2),
        App::Sks => Some(3),
        App::Scrd => Some(4),
        App::Sbio => Some(5),
        App::None => None,
    }
}

/// The apps the discovery must show before the first enable.
const ALL_APPS: [App; 3] = [App::Hdcp, App::Xarm, App::Stac];
/// Every app with buffers: those, sks (stage 6), which the discovery names only after the xART reads, and scrd and
/// sbio (stage 8).
const BUF_APPS: [App; 6] = [App::Hdcp, App::Xarm, App::Stac, App::Sks, App::Scrd, App::Sbio];

fn op_name(op: u8) -> &'static str {
    match op {
        proto::OP_OOL_IN_ADDR => "in address",
        proto::OP_OOL_OUT_ADDR => "out address",
        proto::OP_OOL_IN_SIZE => "in size",
        proto::OP_OOL_OUT_SIZE => "out size",
        proto::OP_SECMODE => "security mode request",
        _ => "?",
    }
}

fn iova_ok(iova: u64, len: usize) -> bool {
    iova % shmem::SEP_PAGE as u64 == 0
        && iova >= WINDOW_BASE
        && iova.checked_add(len as u64).is_some_and(|end| end <= WINDOW_END)
        && (iova >> proto::UNIT_SHIFT) <= u64::from(u32::MAX)
}

/// Nonzero bytes in a buffer and the first one's offset.
fn nonzero(buf: &ShMem, off: usize, len: usize) -> (usize, Option<usize>) {
    // SAFETY: a read of coherent memory the SEP may be writing, for the log only: a torn read only skews it.
    let s = unsafe { &buf.as_ref()[off..off + len] };
    let n = s.iter().filter(|&&b| b != 0).count();
    (n, s.iter().position(|&b| b != 0))
}

fn machine_is_t6034() -> bool {
    let compats: [*const kernel::ffi::c_char; 2] = [c"apple,t6034".as_char_ptr(), core::ptr::null()];
    // SAFETY: a NULL-terminated array of NUL-terminated strings, valid for the call.
    unsafe { bindings::of_machine_compatible_match(compats.as_ptr()) }
}

/// Stage 3's inputs: the `.gl` copy, both root records checked as gl_rec_read checks them, the OS UUID and
/// protected-data-access. Anything missing or wrong and the driver does not attach: nothing is sent.
fn xart_inputs(dev: &device::Device<device::Core<'_>>) -> Result<(Option<xart::Store>, Option<[u8; 16]>, u8)> {
    let fw = match Firmware::request(XART_FW, dev) {
        Ok(fw) => fw,
        Err(e) => {
            dev_err!(dev, "[sep2] stage 3: no apple-sep-xart.gl from the firmware loader ({:?}): not attaching\n", e);
            return Err(e);
        }
    };
    let store = xart::Store::new(&fw).map_err(|why| {
        dev_err!(dev, "[sep2] stage 3: the .gl copy holds {}: not attaching\n", why);
        EINVAL
    })?;
    drop(fw);
    dev_info!(
        dev,
        "[sep2] stage 3: the .gl copy, {:#x} bytes, {} slots, {} used, revision {:#x}, each record as gl_fixup_rev_init wants it; in memory only\n",
        store.size(),
        store.slots(),
        store.used(),
        store.rev()
    );
    for (ty, name) in [(xart::TYPE_ROOT_SEP, "SEP"), (xart::TYPE_ROOT_USER, "user")] {
        match store.find(&xart::root_key(ty), xart::ROOT_MAX) {
            xart::Lookup::Found(r) => dev_info!(
                dev,
                "[sep2] stage 3: the {} root record in slot {}, {:#x} bytes, its CRC-32 good, CRC-16 {:#06x}\n",
                name,
                r.slot,
                r.data.len(),
                xart::crc16(r.data)
            ),
            xart::Lookup::Absent => {
                dev_err!(dev, "[sep2] stage 3: the copy holds no {} root record: not attaching\n", name);
                return Err(ENOENT);
            }
            xart::Lookup::Bad { slot, why } => {
                dev_err!(dev, "[sep2] stage 3: the {} root record in slot {}: {}: not attaching\n", name, slot, why);
                return Err(EINVAL);
            }
        }
    }
    let node = dev.fwnode().ok_or(ENODEV)?;
    let os_uuid = match node.property_count_elem::<u8>(OS_UUID_PROP) {
        Ok(16) => {
            let v = node.property_read_array_vec::<u8>(OS_UUID_PROP, 16)?.required_by(dev)?;
            let mut u = [0u8; 16];
            u.copy_from_slice(&v);
            Some(u)
        }
        Ok(n) => {
            dev_err!(dev, "[sep2] stage 3: apple,os-uuid is {} bytes, not 16: not attaching\n", n);
            return Err(EINVAL);
        }
        Err(_) => None,
    };
    let pda = u8::from(node.property_read::<u32>(PDA_PROP).optional().unwrap_or(1) != 0);
    dev_info!(
        dev,
        "[sep2] stage 3: {}, protected-data-access {}\n",
        if os_uuid.is_some() { "an OS UUID (not logged)" } else { "no OS UUID (op 0x13 gets status 2)" },
        pda
    );
    Ok((Some(store), os_uuid, pda))
}

/// Stage 6's inputs: the SHA bindings checked, set_env's cpx-encryption-mode. A failed check and the driver does
/// not attach: nothing is sent.
fn sks_inputs(dev: &device::Device<device::Core<'_>>) -> Result<u32> {
    if !sks::self_test() {
        dev_err!(dev, "[sep2] stage 6: lib/crypto's SHA-256 or SHA-1 fails FIPS 180's \"abc\" vector: not attaching\n");
        return Err(EINVAL);
    }
    let node = dev.fwnode().ok_or(ENODEV)?;
    let mode = match node.property_read::<u32>(CPX_PROP).optional() {
        Some(m) => {
            dev_info!(dev, "[sep2] stage 6: cpx-encryption-mode {} (sep-on.ko, from the ADT's /defaults)\n", m);
            m
        }
        None => {
            dev_info!(dev, "[sep2] stage 6: no apple,cpx-encryption-mode: the 27.0.1 ADT's {}\n", CPX_DEFAULT);
            CPX_DEFAULT
        }
    };
    Ok(mode)
}

/// Stage 7's identity: the key bag's UUID, its secret, and the uid whose session handle (-uid) it is designated
/// for (evaluate_session_keybag_handle: a uid of 10 or more).
struct Identity {
    uuid: [u8; 16],
    secret: [u8; 32],
    uid: u32,
    /// The wrapped bag a previous run kept, if any.
    bag: Option<KVec<u8>>,
}

/// Stage 7's input: `apple-sep-identity.bin`, made once on the Linux root and kept, so a later run names the same
/// identity. Its UUID and secret are never logged.
fn identity_inputs(dev: &device::Device<device::Core<'_>>) -> Result<Identity> {
    let fw = match Firmware::request(IDENTITY_FW, dev) {
        Ok(fw) => fw,
        Err(e) => {
            dev_err!(dev, "[sep2] stage 7: no apple-sep-identity.bin from the firmware loader ({:?}): not attaching\n", e);
            return Err(e);
        }
    };
    let d = fw.data();
    if d.len() != 52 {
        dev_err!(dev, "[sep2] stage 7: the identity file is {} bytes, not 52: not attaching\n", d.len());
        return Err(EINVAL);
    }
    let mut id = Identity { uuid: [0; 16], secret: [0; 32], uid: u32::from_le_bytes([d[48], d[49], d[50], d[51]]), bag: None };
    id.uuid.copy_from_slice(&d[..16]);
    id.secret.copy_from_slice(&d[16..48]);
    if id.uid < 10 || id.uid > i32::MAX as u32 || id.uuid == [0; 16] || id.secret == [0; 32] {
        dev_err!(dev, "[sep2] stage 7: the identity file holds uid {} (10 or more wanted), or a zero UUID or secret: not attaching\n", id.uid);
        return Err(EINVAL);
    }
    dev_info!(dev, "[sep2] stage 7: the identity file, for uid {} (session handle -{}); its UUID and secret are not logged\n", id.uid, id.uid);
    if let Ok(fw) = Firmware::request_nowarn(IDENTITY_BAG_FW, dev) {
        let b = fw.data();
        if b.is_empty() || b.len() > sks::BUF_LEN / 2 {
            dev_err!(dev, "[sep2] stage 7: the kept bag is {} bytes: not attaching\n", b.len());
            return Err(EINVAL);
        }
        let mut v = KVec::with_capacity(b.len(), GFP_KERNEL)?;
        v.extend_from_slice(b, GFP_KERNEL)?;
        dev_info!(dev, "[sep2] stage 7: a kept bag, {:#x} bytes, sha256 {}\n", v.len(), Hex(&sks::sha256(&v)[..8]));
        id.bag = Some(v);
    } else {
        dev_info!(dev, "[sep2] stage 7: no kept bag: the run creates the identity\n");
    }
    Ok(id)
}

/// debugfs `apple-sep/identity.kb`.
type BagFile = Pin<KBox<debugfs::File<Mutex<KVec<u8>>>>>;

#[pin_data]
struct SepData {
    dev: ARef<device::Device>,
    stage: u32,
    shmem_iova: u64,
    ool_iova: [(u64, u64); 6],
    /// Stage 6: set_env's cpx-encryption-mode.
    cpx_mode: u32,
    /// Stage 7: the identity.
    identity: Option<Identity>,
    /// Stage 7: debugfs `apple-sep/identity.kb`, the wrapped bag copy_keybag returned, for the run to keep.
    bag_file: Option<BagFile>,
    _debugfs: Option<debugfs::Dir>,

    #[pin]
    mbox: Mutex<Option<Mailbox<SepData>>>,
    #[pin]
    bufs: Mutex<Bufs>,
    #[pin]
    state: Mutex<State>,
    #[pin]
    wq: CondVar,

    /// Stage 3: the OS UUID and protected-data-access.
    os_uuid: Option<[u8; 16]>,
    pda: u8,
    /// Stage 3: the `.gl` copy in memory, which stage 5 writes. Its lock makes one xART reply at a time, in the
    /// order the requests came, and is taken before `state` and `bufs`.
    #[pin]
    xart: Mutex<Option<xart::Store>>,

    rx: inbox::Inbox,
    rx_dropped_logged: Atomic<u32>,
    tx_count: Atomic<u32>,
    xarm_held: Atomic<u32>,
    xarm_refused: Atomic<u32>,
    xarm_served: Atomic<u32>,
    shm_given: Atomic<bool>,
    closing: Atomic<bool>,

    #[pin]
    rx_work: Work<SepData, 0>,
    #[pin]
    bringup_work: Work<SepData, 1>,
}

impl_has_work! {
    impl HasWork<Self, 0> for SepData { self.rx_work }
    impl HasWork<Self, 1> for SepData { self.bringup_work }
}

// SAFETY: every field is synchronised (the mutexes, the atomics, the inbox's atomic slots) or
// immutable after construction; the DMA buffers are written only in probe, before the SEP knows them.
unsafe impl Send for SepData {}
// SAFETY: see above.
unsafe impl Sync for SepData {}

impl SepData {
    fn new(pdev: &platform::Device<device::Core<'_>>, stage: u32) -> Result<Arc<SepData>> {
        let dev: &device::Device<device::Core<'_>> = pdev.as_ref();

        let (store, os_uuid, pda) = if stage >= 3 { xart_inputs(dev)? } else { (None, None, 1) };
        let cpx_mode = if stage >= 6 { sks_inputs(dev)? } else { 0 };
        let identity = if stage >= 7 { Some(identity_inputs(dev)?) } else { None };
        let (debugfs, bag_file) = if stage >= 7 {
            let d = debugfs::Dir::new(c"apple-sep");
            let f = KBox::pin_init(d.read_binary_file(c"identity.kb", new_mutex!(KVec::new())), GFP_KERNEL)?;
            (Some(d), Some(f))
        } else {
            (None, None)
        };

        let built = shmem::build(pdev)?;
        let shmem_iova = built.buf.dma_address();
        if !iova_ok(shmem_iova, shmem::SHMEM_SIZE) {
            dev_err!(dev, "[sep2] refusing to attach: the shared memory's address {:#x} is outside the SEP DART's window\n", shmem_iova);
            return Err(EINVAL);
        }
        dev_info!(
            dev,
            "[sep2] shared memory at {:#x}, {:#x} bytes: CINP, GALF, OPLA ({:#x} bytes), IPIS ({:#x}), TOCS, as macOS's\n",
            shmem_iova,
            shmem::SHMEM_SIZE,
            built.opla_len,
            built.ipis_len
        );

        // Only the apps the stage enables get buffers.
        let mut ool: [Option<OolPair>; 6] = [None, None, None, None, None, None];
        let mut ool_iova = [(0u64, 0u64); 6];
        for app in BUF_APPS {
            if stage < 1
                || (app == App::Stac && stage < 2)
                || (app == App::Sks && stage < 6)
                || (matches!(app, App::Scrd | App::Sbio) && stage < 8)
            {
                continue;
            }
            let i = app_index(app).ok_or(EINVAL)?;
            let size = app.ool_size();
            let inbound = dma::Coherent::<u8>::zeroed_slice(dev, size, GFP_KERNEL)?;
            let outbound = dma::Coherent::<u8>::zeroed_slice(dev, size, GFP_KERNEL)?;
            let (a, b) = (inbound.dma_address(), outbound.dma_address());
            if !iova_ok(a, size) || !iova_ok(b, size) {
                dev_err!(dev, "[sep2] refusing to attach: {}'s buffers at {:#x}, {:#x} are outside the SEP DART's window\n", app.name(), a, b);
                return Err(EINVAL);
            }
            dev_info!(dev, "[sep2] {} buffers: in {:#x}, out {:#x}, {:#x} bytes each\n", app.name(), a, b, size);
            ool_iova[i] = (a, b);
            ool[i] = Some(OolPair { inbound, outbound });
        }

        Arc::pin_init(
            try_pin_init!(SepData {
                dev: ARef::<device::Device>::from(pdev.as_ref()),
                stage,
                shmem_iova,
                ool_iova,
                cpx_mode,
                identity,
                bag_file,
                _debugfs: debugfs,
                os_uuid,
                pda,
                xart <- new_mutex!(store),
                mbox <- new_mutex!(None),
                bufs <- new_mutex!(Bufs { shmem: Some(built.buf), ool }),
                state <- new_mutex!(State {
                    ctl: ctl::Slot::new(),
                    rx_total: 0,
                    apps: [DiscApp::EMPTY; MAX_APPS],
                    n_apps: 0,
                    app_wait: None,
                    app_reply: None,
                    serving: false,
                    stopped: None,
                    held: [None; HELD_MAX],
                    n_held: 0,
                    held_lost: 0,
                    sks_wait: None,
                    sks_reply: None,
                    sks: SksCounts {
                        sent: 0,
                        replies: 0,
                        stray: 0,
                        sep_msgs: 0,
                        digest_good: 0,
                        digest_bad: 0,
                        outcome: None,
                        version: 0,
                        identity: None,
                        next_seq: 0,
                    },
                    sbio: SbioCounts::default(),
                }),
                wq <- new_condvar!("SepData::wq"),
                rx: inbox::Inbox::new(),
                rx_dropped_logged: Atomic::new(0),
                tx_count: Atomic::new(0),
                xarm_held: Atomic::new(0),
                xarm_refused: Atomic::new(0),
                xarm_served: Atomic::new(0),
                shm_given: Atomic::new(false),
                closing: Atomic::new(false),
                rx_work <- new_work!("SepData::rx_work"),
                bringup_work <- new_work!("SepData::bringup_work"),
            }),
            GFP_KERNEL,
        )
    }

    /// The only way to the mailbox: refuses anything outside step 2's allowlist.
    fn send(&self, msg: Message, what: &str) -> Result {
        if !proto::allowed(&msg) {
            dev_err!(self.dev, "[sep2] tx REFUSED, not in the allowlist ({}): msg0 {:#018x} msg1 {:#x}\n", what, msg.msg0, msg.msg1);
            return Err(EPERM);
        }
        if self.closing.load(Relaxed) {
            return Err(ENODEV);
        }
        let n = self.tx_count.load(Relaxed) + 1;
        self.tx_count.store(n, Relaxed);
        let f = proto::Word::of(&msg);
        dev_info!(
            self.dev,
            "[sep2] tx #{} ep {:#04x} tag {:#04x} op {:#04x} param {:#04x} data {:#010x} (msg0 {:#018x}): {}\n",
            n,
            f.ep,
            f.tag,
            f.op,
            f.param,
            f.data,
            msg.msg0,
            what
        );
        // The buffers a message points at are written before it: the mailbox leaves the barrier to its callers
        // (rtkit.c has its own).
        barrier::dma_mb(barrier::Write);
        let r = self.mbox.lock().as_ref().ok_or(ENODEV)?.send(msg, false);
        if let Err(e) = r {
            dev_err!(self.dev, "[sep2] tx #{} failed: {:?}\n", n, e);
        }
        r
    }

    fn register(&self) -> Result {
        let msg = proto::shm_register(self.shmem_iova, shmem::SHMEM_SIZE).ok_or(EINVAL)?;
        if REGISTERED.xchg(true, Relaxed) {
            dev_err!(self.dev, "[sep2] the registration was already sent this boot: not again (it is one-shot per reset)\n");
            return Err(EBUSY);
        }
        // Set before the send: the SEP may have the address even if the send reports an error, so the buffers
        // are never freed from here on (remove()).
        self.shm_given.store(true, Relaxed);
        self.send(msg, "shared-memory registration (warm attach)")
    }

    fn rx_total(&self) -> u64 {
        self.state.lock().rx_total
    }

    // --- receive ---

    fn drain(&self) {
        while let Some(msg) = self.rx.get() {
            self.on_message(msg);
        }
        let dropped = self.rx.lost();
        if dropped != self.rx_dropped_logged.load(Relaxed) {
            self.rx_dropped_logged.store(dropped, Relaxed);
            dev_err!(self.dev, "[sep2] receive ring full: {} messages dropped so far\n", dropped);
        }
    }

    fn on_message(&self, msg: Message) {
        let f = proto::Word::of(&msg);
        let mut to_serve = None;
        let mut st = self.state.lock();
        st.rx_total += 1;
        let n = st.rx_total;
        let log = n <= RX_LOG_MAX || n % 256 == 0;

        let dev = &self.dev;
        // The annotation is formatted by its own fmt! (a literal first: its arguments go through the kernel's
        // Display), then printed as one argument of the line.
        macro_rules! rx {
            ($($arg:tt)*) => {
                if log {
                    dev_info!(
                        dev,
                        "[sep2] rx #{} ep {:#04x} tag {:#04x} op {:#04x} param {:#04x} data {:#010x} msg1 {:#x}: {}\n",
                        n, f.ep, f.tag, f.op, f.param, f.data, msg.msg1, fmt!($($arg)*)
                    );
                }
            };
        }

        match f.ep {
            proto::EP_DISCOVER => match f.op {
                proto::DISCOVER_NAME => {
                    if let Some(a) = st.app(f.param) {
                        a.name = Some(f.data);
                    }
                    rx!("discovery: app '{}' at endpoint {:#04x}", FourCc(f.data), f.param);
                }
                proto::DISCOVER_SIZES => {
                    if let Some(a) = st.app(f.param) {
                        a.sizes = Some(f.data);
                    }
                    rx!("discovery: endpoint {:#04x}'s sizes {:#010x}", f.param, f.data);
                }
                _ => rx!("discovery: unknown op"),
            },
            proto::EP_CONTROL if f.tag != 0 => {
                if st.ctl.offer(f) {
                    rx!("control: the answer to the request in flight");
                } else {
                    rx!("control: a tagged message answering nothing in flight (dropped)");
                }
            }
            proto::EP_CONTROL => match f.op {
                0x0d => rx!("control: op 0x0d, timer (not answered)"),
                0x10 => rx!("control: op 0x10, wrapping active (not answered)"),
                0x11 => rx!("control: op 0x11; macOS answers it with op 0x12 (nap ok): NOT answered"),
                0x15 => rx!("control: op 0x15, the OS is active"),
                0x29 => rx!("control: op 0x29, SEP info"),
                _ => rx!("control: unsolicited op (not answered)"),
            },
            proto::EP_XARM => {
                let r = xarm::Req::of(&msg);
                if xarm::is_write(r.op()) && self.stage < 5 {
                    self.xarm_refused.store(self.xarm_refused.load(Relaxed) + 1, Relaxed);
                    dev_warn!(
                        self.dev,
                        "[sep2] xART: REFUSED the SEP's write request (tag {:#04x} op {:#04x}, {}, length {:#x}): no write path here; not serviced, not answered\n",
                        r.tag(),
                        r.op(),
                        xarm::op_name(r.op()),
                        r.len()
                    );
                    if st.serving && st.stopped.is_none() {
                        st.stopped = Some("a write request");
                    }
                }
                let serve = st.serving && st.stopped.is_none();
                if !serve {
                    st.hold(msg);
                    self.xarm_held.store(self.xarm_held.load(Relaxed) + 1, Relaxed);
                }
                let how = if serve { "answered next" } else { "held, not answered" };
                if xarm::is_naming(r.op()) {
                    rx!("xarm: op {:#04x}, {} '{}': {}", r.op(), xarm::op_name(r.op()),
                        FourCc(r.name()), how);
                } else {
                    rx!("xarm: request tag {:#04x} op {:#04x} ({}), length {:#x}, args {:02x} {:02x} {:02x}: {}",
                        r.tag(), r.op(), xarm::op_name(r.op()), r.len(), r.tail()[0], r.tail()[1], r.tail()[2], how);
                }
                if serve {
                    to_serve = Some(msg);
                }
            }
            proto::EP_SKS => {
                let w = sks::decode_word(msg.msg0);
                let cmd = w.cmd & !sks::REPLY_BIT;
                if w.cmd & sks::REPLY_BIT != 0 {
                    if st.sks_wait == Some((cmd, w.seq)) && st.sks_reply.is_none() {
                        st.sks_reply = Some(msg);
                        st.sks.replies += 1;
                        rx!("keystore: the reply to {} (seq {}): status {}, flags {:#06x}, length {:#x}",
                            sks::cmd_name(cmd), w.seq, w.status, w.flags, w.len);
                    } else {
                        st.sks.stray += 1;
                        rx!("keystore: a reply to command {:#04x} seq {} for no request in flight (dropped): status {}, flags {:#06x}, length {:#x}",
                            cmd, w.seq, w.status, w.flags, w.len);
                    }
                } else {
                    // The SEP's own messages (sep_action 0xfffffe0009ce65c4); macOS answers none of them.
                    st.sks.sep_msgs += 1;
                    match w.cmd {
                        3 => rx!("keystore: the SEP's keys-available notice, value {} (not answered)", w.seq),
                        7 => rx!("keystore: the SEP's SE-recovery notice, value {} (not answered)", w.seq),
                        state => rx!("keystore: the SEP's device-state change: handle {}, state {}, value {}, flags {:#04x} (not answered)",
                            (msg.msg0 >> 32) as u32 as i32, state, w.seq, w.status as u8),
                    }
                }
            }
            proto::EP_SBIO if f.tag < proto::GT_FIRST => {
                // AppleMesaSEPDriver::handleSEPMessage's requests (byte 1; bytes 2-3 a length or state, 4-7 the info)
                st.sbio.sep_msgs += 1;
                rx!("sbio: the SEP's own message, request {}, length or state {:#x}, info {:#x} (not answered)",
                    f.tag, u16::from(f.op) | (u16::from(f.param) << 8), f.data);
            }
            proto::EP_HDCP | proto::EP_STAC | proto::EP_SBIO | proto::EP_SCRD
                if st.app_wait == Some(f.ep) && st.app_reply.is_none() =>
            {
                st.app_reply = Some(msg);
                rx!("the reply the bring-up waits for");
            }
            proto::EP_SBIO => {
                st.sbio.sep_msgs += 1;
                rx!("sbio: a packet for no transaction in flight (not answered)");
            }
            proto::EP_SCRD => {
                st.sbio.sep_msgs += 1;
                rx!("scrd: a message for no request in flight (not answered)");
            }
            proto::EP_BOOT => rx!("the boot ROM endpoint (not answered)"),
            proto::EP_SHMEM => rx!("the shared-memory endpoint"),
            proto::EP_HDCP => rx!("hdcp's endpoint (not answered)"),
            proto::EP_STAC => rx!("stac's endpoint (not answered)"),
            _ => rx!("an app's endpoint (not answered)"),
        }
        drop(st);
        self.wq.notify_all();
        if let Some(m) = to_serve {
            self.serve_xarm(m);
        }
    }

    // --- stage 3 ---

    /// Sends `msg` to an app's endpoint and waits for that endpoint's next message.
    fn app_request(&self, msg: Message, what: &str) -> Option<Message> {
        self.app_request_ms(msg, what, APP_TIMEOUT_MS)
    }

    /// As app_request, waiting up to `ms`.
    fn app_request_ms(&self, msg: Message, what: &str, ms: u32) -> Option<Message> {
        let ep = msg.msg0 as u8;
        {
            let mut st = self.state.lock();
            st.app_wait = Some(ep);
            st.app_reply = None;
        }
        if self.send(msg, what).is_err() {
            self.state.lock().app_wait = None;
            return None;
        }
        let mut remaining = time::msecs_to_jiffies(ms);
        let mut st = self.state.lock();
        let reply = loop {
            if let Some(m) = st.app_reply.take() {
                break Some(m);
            }
            if remaining == 0 || self.closing.load(Relaxed) {
                break None;
            }
            remaining = match self.wq.wait_interruptible_timeout(&mut st, remaining) {
                CondVarTimeoutResult::Woken { jiffies } => jiffies,
                CondVarTimeoutResult::Signal { jiffies } => jiffies,
                CondVarTimeoutResult::Timeout => 0,
            };
        };
        st.app_wait = None;
        drop(st);
        if reply.is_none() {
            dev_err!(self.dev, "[sep2] {}: no reply on endpoint {:#04x} within {} ms; stopped, nothing more is sent\n", what, ep, ms);
        }
        reply
    }

    /// hdcp's interface count, then each interface's launch (sep-1.log 1613-1745), before stac's enable.
    fn run_hdcp(&self) -> bool {
        let Some(r) = self.app_request(proto::encode_hdcp(proto::HDCP_OP_COUNT, 0), "hdcp: the interface count") else {
            return false;
        };
        let f = proto::Word::of(&r);
        if f.tag != 0 || f.op != 0 || f.param != 0 || f.data == 0 || f.data > proto::HDCP_MAX_INTERFACES {
            dev_err!(self.dev, "[sep2] hdcp: the count's reply {:#018x} is not 14.8.3's form (result 0, a count of 1-{}); stopped\n", r.msg0, proto::HDCP_MAX_INTERFACES);
            return false;
        }
        dev_info!(self.dev, "[sep2] hdcp: {} interfaces (14.8.3: 14)\n", f.data);
        for i in 0..f.data {
            let Some(r) = self.app_request(proto::encode_hdcp(proto::HDCP_OP_LAUNCH, i as u8), "hdcp: launch an interface") else {
                return false;
            };
            let g = proto::Word::of(&r);
            if g.tag != 0 || g.op != 8 || g.param != 0 || g.data != 0 {
                dev_err!(self.dev, "[sep2] hdcp: interface {}'s reply {:#018x} is not 14.8.3's (result 0, size 8); stopped\n", i, r.msg0);
                return false;
            }
        }
        dev_info!(self.dev, "[sep2] hdcp: all {} interfaces launched, each result 0, size 8\n", f.data);
        true
    }

    /// stac's power-on transaction (sep-1.log 1790): its packet in stac's in buffer, then the word, which the SEP
    /// echoes.
    fn run_stac_power(&self) -> bool {
        {
            let b = self.bufs.lock();
            let Some(p) = &b.ool[2] else {
                return false;
            };
            // SAFETY: the SEP reads stac's in buffer only for a message that names it, sent after this write.
            let buf = unsafe { p.inbound.as_mut() };
            if proto::gt_packet(proto::GT_POWER, 0, &1u32.to_le_bytes(), buf).is_none() {
                return false;
            }
        }
        let msg = proto::encode_gt(proto::GT_POWER);
        let Some(r) = self.app_request(msg, "stac: the power-on transaction") else {
            return false;
        };
        if r.msg0 != msg.msg0 || r.msg1 != 0 {
            dev_err!(self.dev, "[sep2] stac: the reply {:#018x} is not the echo 14.8.3 got; stopped\n", r.msg0);
            return false;
        }
        barrier::dma_mb(barrier::Read);
        let b = self.bufs.lock();
        if let Some(p) = &b.ool[2] {
            // SAFETY: a read of coherent memory the SEP wrote before its reply, for the log only.
            let o = unsafe { &p.outbound.as_ref()[..proto::GT_HEADER + 4] };
            let w = |i: usize| u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]);
            dev_info!(
                self.dev,
                "[sep2] stac: powered on; the out buffer's packet header {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}, then {:#x}\n",
                w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7)
            );
        }
        true
    }

    /// Writes `d` at `off` in xarm's in buffer, which the SEP reads for the reply that follows.
    fn xarm_in_write(&self, off: usize, d: &[u8], zero: usize) -> core::result::Result<(), &'static str> {
        let b = self.bufs.lock();
        let p = b.ool[1].as_ref().ok_or("no xarm buffers")?;
        // SAFETY: the SEP waits for the reply to its request before it reads xarm's in buffer, and one reply is
        // made at a time (the xart lock).
        let buf = unsafe { p.inbound.as_mut() };
        let end = off.checked_add(d.len()).ok_or("too long")?;
        if end > buf.len() || zero > off {
            return Err("larger than xarm's in buffer");
        }
        buf[..zero].fill(0);
        buf[off..end].copy_from_slice(d);
        Ok(())
    }

    /// A root read (op 0): byte 0 and the zero UUID, then the record, as _handle_sep_driven_msg lays them out.
    fn root_read(&self, store: &xart::Store, msg: &Message, r: &xarm::Req) -> core::result::Result<Message, &'static str> {
        let sep = r.owner() & 1 != 0;
        let ty = if sep { xart::TYPE_ROOT_SEP } else { xart::TYPE_ROOT_USER };
        let rec = match store.find(&xart::root_key(ty), xart::ROOT_MAX) {
            xart::Lookup::Found(rec) => rec,
            xart::Lookup::Absent => return Err("a root read the copy holds no record for"),
            xart::Lookup::Bad { why, .. } => return Err(why),
        };
        let len = u16::try_from(xart::ROOT_PREFIX + rec.data.len()).map_err(|_| "too long")?;
        self.xarm_in_write(xart::ROOT_PREFIX, rec.data, xart::ROOT_PREFIX)?;
        dev_info!(
            self.dev,
            "[sep2] xART: the {} root record, slot {}, {:#x} bytes, CRC-16 {:#06x} (macOS logs 'Fetched {}-xART with CRC')\n",
            if sep { "SEP" } else { "user" },
            rec.slot,
            rec.data.len(),
            xart::crc16(rec.data),
            if sep { "SEP" } else { "USER" }
        );
        Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, len, None))
    }

    /// The first `len` bytes of xarm's out buffer, which the SEP wrote before its request, handed to `f`.
    fn with_xarm_out<R>(&self, len: usize, f: impl FnOnce(&[u8]) -> R) -> core::result::Result<R, &'static str> {
        barrier::dma_mb(barrier::Read);
        let b = self.bufs.lock();
        let p = b.ool[1].as_ref().ok_or("no xarm buffers")?;
        // SAFETY: the SEP wrote the request's bytes before it and waits for the reply; one reply is made at a time.
        let o = unsafe { p.outbound.as_ref() };
        Ok(f(o.get(..len).ok_or("longer than xarm's out buffer")?))
    }

    /// The 16 bytes at 0 of xarm's out buffer: a session request's UUID.
    fn xarm_out_uuid(&self) -> core::result::Result<[u8; 16], &'static str> {
        self.with_xarm_out(16, |o| {
            let mut u = [0u8; 16];
            u.copy_from_slice(o);
            u
        })
    }

    /// A session read (op 5, a locker): the key's UUID from xarm's out buffer, the record at 0 of its in
    /// buffer, its length in the reply; no record is status 0 with nothing (_handle_sep_driven_msg's case 5).
    /// The UUID is not logged.
    fn session_read(&self, store: &xart::Store, msg: &Message, r: &xarm::Req) -> core::result::Result<Message, &'static str> {
        let sep = r.owner() & 1 != 0;
        let ty = if sep { xart::TYPE_SESSION_SEP } else { xart::TYPE_SESSION_USER };
        let uuid = self.xarm_out_uuid()?;
        let who = if sep { "SEP" } else { "USER" };
        match store.find(&xart::session_key(ty, &uuid), xart::SESSION_MAX) {
            xart::Lookup::Found(rec) => {
                let len = u16::try_from(rec.data.len()).map_err(|_| "too long")?;
                self.xarm_in_write(0, rec.data, 0)?;
                dev_info!(
                    self.dev,
                    "[sep2] xART: a {} locker, slot {}, {:#x} bytes, CRC-16 {:#06x} (macOS logs 'Fetched {}-xART Locker with CRC')\n",
                    who,
                    rec.slot,
                    rec.data.len(),
                    xart::crc16_from(xart::crc16(&uuid), rec.data),
                    who
                );
                Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, len, None))
            }
            xart::Lookup::Absent => {
                dev_info!(self.dev, "[sep2] xART: no {} locker for the key: status 0, nothing\n", who);
                Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, None))
            }
            xart::Lookup::Bad { why, .. } => Err(why),
        }
    }

    // --- stage 5: the writes, into the copy in memory ---

    /// A write's byte 5: bit 0 the owner, the SEP's records or the user's. macOS reads only that bit; the traces
    /// have no other set.
    fn write_owner(r: &xarm::Req) -> core::result::Result<bool, &'static str> {
        match r.owner() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("a write whose byte 5 holds more than the owner bit"),
        }
    }

    /// Stage 7: a root write (op 1) or a locker write (op 6) is logged and held, never answered. An answer would let
    /// the SEP count a write that no disk has, its anti-replay state then ahead of the `.gl` macOS reads
    /// (TOUCHID.md). The log: the op, the owner, the length, the CRC-16's check (the record at 0 of xarm's out
    /// buffer, a locker's after its UUID; _handle_sep_driven_msg's cases 1 and 6) and whether the key holds a record;
    /// never the bytes or the UUID.
    fn write_held(&self, store: &xart::Store, r: &xarm::Req) -> &'static str {
        let sep = match Self::write_owner(r) {
            Ok(sep) => sep,
            Err(why) => return why,
        };
        let root = r.op() == xarm::OP_ROOT_WRITE;
        let len = usize::from(r.len());
        let seen = self.with_xarm_out(len.min(xart::DATA_MAX), |o| {
            let key = if root {
                Some(xart::root_key(if sep { xart::TYPE_ROOT_SEP } else { xart::TYPE_ROOT_USER }))
            } else if o.len() >= 16 {
                let mut u = [0u8; 16];
                u.copy_from_slice(&o[..16]);
                Some(xart::session_key(if sep { xart::TYPE_SESSION_SEP } else { xart::TYPE_SESSION_USER }, &u))
            } else {
                None
            };
            (xart::crc16(o) == r.crc16(), key.and_then(|k| store.slot_of(&k)))
        });
        let what = if root { "a root record" } else { "a locker" };
        let who = if sep { "SEP" } else { "user" };
        match seen {
            Ok((crc_ok, Some(slot))) => dev_info!(
                self.dev,
                "[sep2] xART: op {:#04x}, {} of the {}'s: {:#x} bytes, CRC-16 {:#06x} {}, its key's record in slot {}: held, never answered\n",
                r.op(), what, who, len, r.crc16(), if crc_ok { "good" } else { "BAD" }, slot
            ),
            Ok((crc_ok, None)) => dev_info!(
                self.dev,
                "[sep2] xART: op {:#04x}, {} of the {}'s: {:#x} bytes, CRC-16 {:#06x} {}, a new key: held, never answered\n",
                r.op(), what, who, len, r.crc16(), if crc_ok { "good" } else { "BAD" }
            ),
            Err(why) => dev_info!(self.dev, "[sep2] xART: op {:#04x}, {} of the {}'s, {:#x} bytes ({}): held, never answered\n", r.op(), what, who, len, why),
        }
        self.xarm_refused.store(self.xarm_refused.load(Relaxed) + 1, Relaxed);
        "an xART write: held, never answered (no write path to the disk)"
    }

    /// A session delete (op 7): the UUID at 0 of xarm's out buffer, the key type 4 or 3; no record is status 0 with
    /// nothing deleted, as macOS 14.8.3 answered at sep-1.log 2081 (_handle_sep_driven_msg's case 7, which checks
    /// no CRC-16 and takes 0x10-0x8000 bytes; the traces have 0x10).
    fn session_delete(&self, store: &mut xart::Store, msg: &Message, r: &xarm::Req) -> core::result::Result<Message, &'static str> {
        let sep = Self::write_owner(r)?;
        if r.len() != 0x10 {
            return Err("a session delete whose length is not 0x10");
        }
        let ty = if sep { xart::TYPE_SESSION_SEP } else { xart::TYPE_SESSION_USER };
        let who = if sep { "SEP" } else { "USER" };
        let uuid = self.xarm_out_uuid()?;
        match store.slot_of(&xart::session_key(ty, &uuid)) {
            None => dev_info!(
                self.dev,
                "[sep2] xART: op 0x07, no {} locker for the key: nothing deleted, status 0 (macOS logs '{}_XART_LOCKER ... not found')\n",
                who,
                who
            ),
            // The disk would keep a found record, behind the SEP after a reboot: not served before a disk write path.
            Some(slot) => {
                dev_info!(self.dev, "[sep2] xART: op 0x07 finds a {} locker in slot {}: not served\n", who, slot);
                return Err("a delete that finds its record: the step ends here");
            }
        }
        Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, None))
    }

    /// One request's reply, as macOS 14.8.3 makes it, or the reason the service stops.
    fn xarm_reply(&self, store: &mut Option<xart::Store>, msg: &Message) -> core::result::Result<Message, &'static str> {
        let r = xarm::Req::of(msg);
        match r.op() {
            // A served write would leave the disk behind the SEP's anti-replay state after a reboot (step 5's
            // report): op 1 and op 6 are never answered; at stage 7 they are logged first.
            xarm::OP_ROOT_WRITE | xarm::OP_SESSION_WRITE if self.stage >= 7 => {
                Err(self.write_held(store.as_ref().ok_or("no .gl copy")?, &r))
            }
            xarm::OP_SESSION_DELETE if self.stage >= 5 => self.session_delete(store.as_mut().ok_or("no .gl copy")?, msg, &r),
            _ if xarm::is_write(r.op()) => Err("a state-changing write: the step ends here"),
            xarm::OP_QUERY_PROTECTED if r.len() == 0 => Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, Some(self.pda))),
            xarm::OP_GET_OS_UUID if r.len() == 0 => match &self.os_uuid {
                Some(u) => {
                    self.xarm_in_write(0, u, 0)?;
                    Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, None))
                }
                None => Ok(xarm::Req::of(msg).answer(xarm::STATUS_NO_UUID, 0, None)),
            },
            xarm::OP_ROOT_READ if r.len() == 0 => self.root_read(store.as_ref().ok_or("no .gl copy")?, msg, &r),
            o if xarm::is_naming(o) => Ok(xarm::Req::of(msg).answer(xarm::STATUS_UNKNOWN_OP, 0, None)),
            xarm::OP_SESSION_READ if self.stage >= 4 && r.len() == 0x10 => {
                self.session_read(store.as_ref().ok_or("no .gl copy")?, msg, &r)
            }
            xarm::OP_SESSION_READ if self.stage >= 4 => Err("a session read whose length is not 0x10"),
            xarm::OP_SESSION_READ => Err("the first session read: step 3 ends here"),
            _ => Err("a request this stage serves neither as a read nor as a write"),
        }
    }

    /// Stage 7: the ops macOS 27.2's xART service has and 14.8.3's lacks (rda AppleSEPManager_272,
    /// AppleSEPXART::_handle_sep_driven_msg 0xfffffe0009db4b24), as 27.2 handles them. 0x1d (register_disable, a 4CC
    /// in bytes 3-6), 0x1e (log_disable_begin) and 0x1f (log_disable_acknowledge) go to its XARTDisableLog and are
    /// never answered; 0x21 (the SEP's secure storage analytics: a version byte and a u32 at 0 of xarm's out buffer,
    /// 5 bytes) is answered status 0, length 0. True if `msg` was one of them.
    fn serve_27(&self, msg: &Message) -> bool {
        let r = xarm::Req::of(msg);
        match r.op() {
            0x1d..=0x1f => {
                let b = msg.msg0.to_le_bytes();
                let cc = [b[3], b[4], b[5], b[6]];
                let shown = if cc.iter().all(|c| c.is_ascii_graphic()) { core::str::from_utf8(&cc).unwrap_or("?") } else { "?" };
                dev_info!(self.dev, "[sep2] xART: op {:#04x} ({}), '{}': logged, not answered, as macOS 27.2\n", r.op(),
                    match r.op() { 0x1d => "register_disable", 0x1e => "log_disable_begin", _ => "log_disable_acknowledge" }, shown);
                self.xarm_served.store(self.xarm_served.load(Relaxed) + 1, Relaxed);
                true
            }
            0x21 if r.len() != 0 => {
                let seen = self.with_xarm_out(5, |o| (o[0], u32::from_le_bytes([o[1], o[2], o[3], o[4]])));
                match seen {
                    Ok((v, x)) => dev_info!(self.dev, "[sep2] xART: op 0x21, the secure storage analytics: {:#x} bytes, version {}, value {:#x}: status 0\n", r.len(), v, x),
                    Err(why) => dev_info!(self.dev, "[sep2] xART: op 0x21, the secure storage analytics ({}): status 0\n", why),
                }
                if self.send(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, None), "analytics").is_ok() {
                    self.xarm_served.store(self.xarm_served.load(Relaxed) + 1, Relaxed);
                } else {
                    self.state.lock().stopped = Some("a reply's send failed");
                }
                true
            }
            _ => false,
        }
    }

    fn serve_one(&self, store: &mut Option<xart::Store>, msg: Message) {
        {
            let mut st = self.state.lock();
            if st.stopped.is_some() {
                st.hold(msg);
                drop(st);
                self.xarm_held.store(self.xarm_held.load(Relaxed) + 1, Relaxed);
                return;
            }
        }
        if self.stage >= 7 && self.serve_27(&msg) {
            return;
        }
        match self.xarm_reply(store, &msg) {
            Ok(reply) => {
                let r = xarm::Req::of(&msg);
                if self.send(reply, xarm::op_name(r.op())).is_ok() {
                    self.xarm_served.store(self.xarm_served.load(Relaxed) + 1, Relaxed);
                } else {
                    self.state.lock().stopped = Some("a reply's send failed");
                }
            }
            Err(why) => {
                let mut st = self.state.lock();
                st.stopped = Some(why);
                st.hold(msg);
                drop(st);
                self.xarm_held.store(self.xarm_held.load(Relaxed) + 1, Relaxed);
                dev_info!(self.dev, "[sep2] xART: the service stops at {:#018x}: {}; it and every request after it are held\n", msg.msg0, why);
            }
        }
    }

    fn serve_xarm(&self, msg: Message) {
        let mut store = self.xart.lock();
        self.serve_one(&mut store, msg);
    }

    /// Opens the xART service on the `.gl` copy: what was held is answered in order, then each request as it comes.
    fn open_xart(&self) {
        let mut store = self.xart.lock();
        let mut held = [None; HELD_MAX];
        let n = {
            let mut st = self.state.lock();
            st.serving = true;
            let n = st.n_held;
            held[..n].copy_from_slice(&st.held[..n]);
            st.n_held = 0;
            n
        };
        dev_info!(self.dev, "[sep2] xART: the service opens on the .gl copy, {} requests held before\n", n);
        for m in held[..n].iter().flatten() {
            self.serve_one(&mut store, *m);
        }
    }

    // --- stage 6: the key store ---

    /// Waits for the discovery to name endpoint 0x12 (its 4CC and its sizes); false if it does not within
    /// SKS_ANNOUNCE_MS, if the xART service stops first, or if the driver is going away.
    fn wait_sks_announced(&self) -> bool {
        let mut waited = 0;
        loop {
            {
                let st = self.state.lock();
                if let Some(why) = st.stopped {
                    dev_err!(self.dev, "[sep2] keystore: the xART service stopped at {} before the discovery named endpoint {:#04x}: not enabled\n", why, proto::EP_SKS);
                    return false;
                }
                if st.find(proto::EP_SKS).is_some_and(|a| a.name.is_some() && a.sizes.is_some()) {
                    break;
                }
            }
            if waited >= SKS_ANNOUNCE_MS {
                dev_err!(self.dev, "[sep2] keystore: the discovery did not name endpoint {:#04x} within {} ms of the xART service's opening: not enabled\n", proto::EP_SKS, SKS_ANNOUNCE_MS);
                return false;
            }
            if !self.nap(POLL_MS) {
                return false;
            }
            waited += POLL_MS;
        }
        dev_info!(self.dev, "[sep2] keystore: the discovery named endpoint {:#04x} {} ms after the xART service opened\n", proto::EP_SKS, waited);
        true
    }

    /// Parses a reply image as the coders do and logs it: the header, the digest's check (a mismatch is logged and
    /// counted only; macOS logs "ipc digest failed" and refuses the reply), the body's first bytes.
    fn log_reply<'a>(&self, name: &str, img: &'a [u8]) -> Option<sks::ReplyImage<'a>> {
        let r = match sks::parse_reply(img) {
            Ok(r) => r,
            Err(why) => {
                dev_err!(self.dev, "[sep2] keystore: {}'s reply image does not parse as the coders parse it: {}\n", name, why);
                return None;
            }
        };
        {
            let mut st = self.state.lock();
            match r.digest_ok {
                Some(true) => st.sks.digest_good += 1,
                Some(false) => st.sks.digest_bad += 1,
                None => {}
            }
        }
        // a copied bag's or UUID's bytes are not logged: the version word and the blob's length only
        let shown = r.body.len().min(if name.starts_with("copy_keybag") { 8 } else { 32 });
        dev_info!(
            self.dev,
            "[sep2] keystore: {}'s reply: header {:#x} bytes, v{}, flags {:#x}, time {} us, {}; body {:#x} bytes: {}{}\n",
            name,
            r.header_len,
            r.version,
            r.flags,
            r.usec,
            match r.digest_ok {
                Some(true) => "digest good",
                Some(false) => "digest MISMATCH (logged only)",
                None => "digest not checked (a header version __payload_hash refuses)",
            },
            r.body.len(),
            Hex(&r.body[..shown]),
            if r.body.len() > shown { " ..." } else { "" }
        );
        if let Some(n) = r.ext_len {
            dev_info!(self.dev, "[sep2] keystore: {}'s reply carries an extended header of {:#x} bytes (device state; not decoded)\n", name, n);
        }
        if r.flags & 1 != 0 {
            dev_warn!(self.dev, "[sep2] keystore: {}'s reply header says encrypted (flags bit 0), which macOS refuses\n", name);
        }
        Some(r)
    }

    /// One key store request (sep_deliver_msg_gated): its image at 0 of sks's in buffer, the word, then the wait
    /// for the reply that names its command and sequence number. The reply's word and image, or None (logged), which
    /// ends the start-up.
    fn sks_call(&self, src: &str, cmd: u8, seq: u8, version: u32, body: &sks::Body) -> Option<(sks::Word, KVec<u8>)> {
        let name = sks::cmd_name(cmd);
        if let Some(why) = self.state.lock().stopped {
            dev_err!(self.dev, "[sep2] keystore: the xART service stopped at {}: {} is not sent\n", why, name);
            return None;
        }
        // SAFETY: reads of the kernel's clocks, callable from any context but NMI.
        let (boot_ns, real_s) = unsafe { (bindings::ktime_get_boottime(), bindings::ktime_get_real_seconds()) };
        // get_usec_time: the continuous time (sleep included) in us; get_clock_time: calendar seconds (v2 only)
        let usec = u64::try_from(boot_ns / 1000).unwrap_or(0);
        let img = match sks::build_request(version, usec, u64::try_from(real_s).unwrap_or(0), body) {
            Ok(img) => img,
            Err(e) => {
                dev_err!(self.dev, "[sep2] keystore: {}'s image not built ({:?})\n", name, e);
                return None;
            }
        };
        let len = u16::try_from(img.len()).ok()?;
        {
            let b = self.bufs.lock();
            let Some(p) = &b.ool[3] else {
                dev_err!(self.dev, "[sep2] keystore: no sks buffers\n");
                return None;
            };
            // SAFETY: the SEP reads sks's in buffer only for a request that names it and writes its out buffer only
            // for a reply; none is in flight: one request at a time, the last one answered or the start-up ended.
            unsafe {
                let i = p.inbound.as_mut();
                i.fill(0);
                i[..img.len()].copy_from_slice(&img);
                p.outbound.as_mut().fill(0);
            }
        }
        dev_info!(
            self.dev,
            "[sep2] keystore: request ({}): {}, seq {}, header v{}, image {:#x} bytes, digest {}\n",
            src,
            name,
            seq,
            version,
            img.len(),
            Hex(&img[4..4 + sks::DIGEST_LEN])
        );
        {
            let mut st = self.state.lock();
            st.sks_wait = Some((cmd, seq));
            st.sks_reply = None;
        }
        let msg = Message {
            msg0: sks::request_word(cmd, seq, len),
            msg1: 0,
        };
        if self.send(msg, name).is_err() {
            self.state.lock().sks_wait = None;
            dev_err!(self.dev, "[sep2] keystore: {}'s send failed\n", name);
            return None;
        }

        let mut remaining = time::msecs_to_jiffies(sks::TIMEOUT_MS);
        let mut st = self.state.lock();
        st.sks.sent += 1;
        let reply = loop {
            if let Some(m) = st.sks_reply.take() {
                break Some(m);
            }
            if remaining == 0 || self.closing.load(Relaxed) {
                break None;
            }
            remaining = match self.wq.wait_interruptible_timeout(&mut st, remaining) {
                CondVarTimeoutResult::Woken { jiffies } => jiffies,
                CondVarTimeoutResult::Signal { jiffies } => jiffies,
                CondVarTimeoutResult::Timeout => 0,
            };
        };
        st.sks_wait = None;
        drop(st);
        let Some(r) = reply else {
            dev_err!(
                self.dev,
                "[sep2] keystore: no reply to {} (seq {}) within {} ms (macOS: 'sks timeout strike'); the start-up ends, nothing more goes to endpoint {:#04x}\n",
                name,
                seq,
                sks::TIMEOUT_MS,
                proto::EP_SKS
            );
            return None;
        };
        let w = sks::decode_word(r.msg0);
        let rlen = usize::from(w.len);
        if rlen > sks::BUF_LEN {
            dev_err!(self.dev, "[sep2] keystore: {}'s reply image is {:#x} bytes, more than the buffer (macOS refuses it)\n", name, rlen);
            return None;
        }
        barrier::dma_mb(barrier::Read);
        let mut out = KVec::new();
        {
            let b = self.bufs.lock();
            let p = b.ool[3].as_ref()?;
            // SAFETY: the SEP wrote the reply image before the reply's word and writes nothing more before the next
            // request.
            let o = unsafe { p.outbound.as_ref() };
            if out.extend_from_slice(&o[..rlen], GFP_KERNEL).is_err() {
                dev_err!(self.dev, "[sep2] keystore: no memory for {}'s reply image\n", name);
                return None;
            }
        }
        if rlen > 0 {
            let shown = rlen.min(32);
            dev_info!(
                self.dev,
                "[sep2] keystore: {}'s reply image, {:#x} bytes: {}{}\n",
                name,
                rlen,
                Hex(&out[..shown]),
                if rlen > shown { " ..." } else { "" }
            );
        }
        Some((w, out))
    }

    /// Records how the start-up ended; false, for the caller to return.
    fn sks_end(&self, why: &'static str) -> bool {
        self.state.lock().sks.outcome = Some(why);
        false
    }

    /// The key store's start-up as init_sep_endpoint and effaceable_init send it (sep-1.log 2184-2225), without
    /// 0x22, which only seeds macOS's PRNG: true if each answer is 14.8.3's.
    fn sks_startup(&self) -> bool {
        // get_capabilities: struct version 0, u64 1, an empty blob, header v1 (init_sep_endpoint's xmmword's version)
        let Ok(body) = sks::body_start().and_then(|b| b.blob(&[])) else {
            return self.sks_end("no memory");
        };
        let Some((w, img)) = self.sks_call("1/3, sep-1.log:2184", sks::CMD_GET_CAPABILITIES, 1, 1, &body) else {
            return self.sks_end("get_capabilities had no usable reply");
        };
        let parsed = if w.len > 0 { self.log_reply("get_capabilities", &img) } else { None };
        let caps = parsed.and_then(|r| sks::parse_capabilities(r.body));
        let Some((theirs, blob)) = caps.filter(|_| w.status == 0 && w.len == 0x5c) else {
            dev_err!(
                self.dev,
                "[sep2] keystore: get_capabilities' answer is not 14.8.3's (status 0, 0x5c bytes: version 0, the SEP's header version, an empty blob): status {}, {:#x} bytes; the start-up ends\n",
                w.status,
                w.len
            );
            return self.sks_end("get_capabilities' answer is not 14.8.3's");
        };
        let negotiated = u32::try_from(theirs.min(u64::from(sks::OUR_VERSION))).unwrap_or(0);
        dev_info!(
            self.dev,
            "[sep2] keystore: negotiated to ipc header theirs:v{}, ours:v{} -> negotiated:v{} (14.8.3: theirs v2); call flags {:#x}, blob {} bytes\n",
            theirs,
            sks::OUR_VERSION,
            negotiated,
            w.flags,
            blob
        );
        if negotiated == 0 {
            dev_err!(self.dev, "[sep2] keystore: header version 0, which __payload_hash refuses; the start-up ends\n");
            return self.sks_end("the SEP's header version is 0");
        }
        self.state.lock().sks.version = negotiated;

        // set_env(false): struct version 0, u64 1, the 0x40c-byte environment
        let Ok(body) = sks::body_start().and_then(|b| b.blob(&sks::set_env_blob(self.cpx_mode))) else {
            return self.sks_end("no memory");
        };
        let Some((w, img)) = self.sks_call("2/3, sep-1.log:2193", sks::CMD_SET_ENV, 2, negotiated, &body) else {
            return self.sks_end("set_env had no usable reply");
        };
        let parsed = if w.len > 0 { self.log_reply("set_env", &img) } else { None };
        let ok = parsed.is_some_and(|r| sks::parse_version_only(r.body));
        if !ok || w.status != 0 || w.len != 0x58 {
            dev_err!(
                self.dev,
                "[sep2] keystore: set_env's answer is not 14.8.3's (status 0, 0x58 bytes: version 0 alone): status {}, {:#x} bytes; the start-up ends\n",
                w.status,
                w.len
            );
            return self.sks_end("set_env's answer is not 14.8.3's");
        }
        dev_info!(self.dev, "[sep2] keystore: set_env took cpx-encryption-mode {}: status 0, as on 14.8.3\n", self.cpx_mode);

        // null_d_key: struct version 0, u64 1 (effaceable_init, with /defaults/no-effaceable-storage)
        let Ok(body) = sks::body_start() else {
            return self.sks_end("no memory");
        };
        let Some((w, img)) = self.sks_call("3/3, sep-1.log:2221", sks::CMD_NULL_D_KEY, 3, negotiated, &body) else {
            return self.sks_end("null_d_key had no usable reply");
        };
        if w.len > 0 {
            self.log_reply("null_d_key", &img);
        }
        if w.status != -1 {
            dev_err!(
                self.dev,
                "[sep2] keystore: null_d_key answered status {} ({:#x} bytes), not 14.8.3's -1: a surprise; the start-up ends\n",
                w.status,
                w.len
            );
            return self.sks_end("null_d_key's answer is not 14.8.3's -1");
        }
        dev_info!(self.dev, "[sep2] keystore: null_d_key answered -1 ({:#x} bytes), as 14.8.3's, which logs it and goes on\n", w.len);
        self.state.lock().sks.outcome = Some("done as on macOS 14.8.3 (0, 0, -1)");
        true
    }

    /// Stage 6: sks's enable once the discovery names it, then the key store's start-up.
    fn run_sks(&self) -> bool {
        if !self.wait_sks_announced() {
            return self.sks_end("sks was never named, so never enabled");
        }
        if !self.check_apps(&[App::Sks]) {
            return self.sks_end("sks is not as on 14.8.3, so not enabled");
        }
        if !self.run_steps("sks", &proto::STAGE6) {
            return self.sks_end("sks's enable stopped");
        }
        if !self.sks_startup() {
            return false;
        }
        self.stage < 7 || self.run_identity()
    }

    /// Records how the identity's sequence ended; false, for the caller to return.
    fn identity_end(&self, why: &'static str) -> bool {
        dev_err!(self.dev, "[sep2] identity: {}; the sequence ends, nothing more goes to endpoint {:#04x}\n", why, proto::EP_SKS);
        self.state.lock().sks.identity = Some(why);
        false
    }

    /// One identity request: its reply's word and parsed image, or None (logged), and a status other than 0 is
    /// logged as the SEP's refusal.
    fn identity_call(&self, step: &str, cmd: u8, seq: u8, body: Result<sks::Body>) -> Option<(sks::Word, KVec<u8>)> {
        let version = self.state.lock().sks.version;
        let Ok(body) = body else {
            dev_err!(self.dev, "[sep2] identity: no memory for {}'s body\n", sks::cmd_name(cmd));
            return None;
        };
        let (w, img) = self.sks_call(step, cmd, seq, version, &body)?;
        if w.status != 0 {
            dev_err!(self.dev, "[sep2] identity: {} answered status {} ({:#x} bytes)\n", sks::cmd_name(cmd), w.status, w.len);
            if w.len > 0 {
                self.log_reply(sks::cmd_name(cmd), &img);
            }
            return None;
        }
        Some((w, img))
    }

    /// The body of a reply image as the coders parse it, or an empty slice.
    fn reply_body<'a>(&self, cmd: u8, img: &'a [u8]) -> &'a [u8] {
        self.log_reply(sks::cmd_name(cmd), img).map(|r| r.body).unwrap_or(&[])
    }

    /// A read of a handle's state (get_device_state), logged whole up to 0x100 bytes: its lock state (`sls`), if
    /// any. Never ends the sequence.
    fn state_probe(&self, step: &str, handle: i32, seq: u8) -> Option<u8> {
        let (_, img) = self.identity_call(step, sks::CMD_GET_DEVICE_STATE, seq, sks::get_device_state(handle))?;
        let Some(b) = sks::parse_blob(self.reply_body(sks::CMD_GET_DEVICE_STATE, &img)) else {
            dev_err!(self.dev, "[sep2] identity: get_device_state's reply is not {{0, blob}}\n");
            return None;
        };
        dev_info!(self.dev, "[sep2] identity: handle {}'s state, {:#x} bytes: {}\n", handle, b.len(), Hex(&b[..b.len().min(0x100)]));
        sks::lock_state(b)
    }

    /// Stage 7: Linux's identity key bag, kept by the host: with no kept bag, created (v5) and copied out wrapped
    /// (copy_keybag_uuid, copy_keybag, unload), then loaded from the wrapped bag, designated for
    /// the session (make_system_keybag v1, unload; identity_load's tail) and unlocked (device_state_transition, as
    /// AKSIdentityUnlockSession unlocks it). One request at a time; any other answer, or an xART write held on the way,
    /// ends it.
    fn run_identity(&self) -> bool {
        let Some(id) = self.identity.as_ref() else {
            return self.identity_end("no identity file");
        };
        let session = -(id.uid as i32);
        let mut seq = 4u8;
        let mut next = || {
            seq += 1;
            seq - 1
        };

        let kept;
        let made;
        let bag: &[u8] = match id.bag.as_deref() {
            Some(b) => {
                kept = true;
                b
            }
            None => {
                kept = false;
                // identity_create: create v5 with options 0 (no SEP-resident identity: load_keybag by the UUID
                // answers -3 on 27.2's sepOS, 2026-11-07)
                let Some((_, img)) = self.identity_call("7.1 create", sks::CMD_CREATE_KEYBAG, next(), sks::create_identity(&id.secret, &id.uuid)) else {
                    return self.identity_end("create_keybag v5 was not answered status 0");
                };
                let Some((h, fv)) = sks::parse_create_v5(self.reply_body(sks::CMD_CREATE_KEYBAG, &img)) else {
                    return self.identity_end("create_keybag's reply is not v5's {5, handle, fv_data}");
                };
                dev_info!(self.dev, "[sep2] identity: created, handle {}, fv_data {:#x} bytes\n", h, fv);
                let Some((_, img)) = self.identity_call("7.2 copy_keybag_uuid", sks::CMD_COPY_KEYBAG_UUID, next(), sks::copy_keybag_uuid(h)) else {
                    return self.identity_end("copy_keybag_uuid was not answered status 0");
                };
                let Some(u) = sks::parse_blob(self.reply_body(sks::CMD_COPY_KEYBAG_UUID, &img)) else {
                    return self.identity_end("copy_keybag_uuid's reply is not {0, blob}");
                };
                let same = if u == id.uuid.as_slice() { "equal to" } else { "not" };
                dev_info!(self.dev, "[sep2] identity: the bag's UUID, {} bytes, {} the identity file's\n", u.len(), same);
                let Some((_, img)) = self.identity_call("7.3 copy_keybag", sks::CMD_COPY_KEYBAG, next(), sks::copy_keybag(h)) else {
                    return self.identity_end("copy_keybag was not answered status 0");
                };
                let Some(w) = sks::parse_blob(self.reply_body(sks::CMD_COPY_KEYBAG, &img)) else {
                    return self.identity_end("copy_keybag's reply is not {0, blob}");
                };
                if w.is_empty() {
                    return self.identity_end("copy_keybag returned an empty bag");
                }
                let mut v = KVec::new();
                if v.extend_from_slice(w, GFP_KERNEL).is_err() {
                    return self.identity_end("no memory for the wrapped bag");
                }
                dev_info!(self.dev, "[sep2] identity: the wrapped bag, {:#x} bytes, sha256 {}\n", v.len(), Hex(&sks::sha256(&v)[..8]));
                if let Some(f) = self.bag_file.as_ref() {
                    let mut c = KVec::new();
                    if c.extend_from_slice(&v, GFP_KERNEL).is_ok() {
                        *f.lock() = c;
                    }
                }
                let Some((_, img)) = self.identity_call("7.4 unload", sks::CMD_UNLOAD_KEYBAG, next(), sks::unload_keybag(h)) else {
                    return self.identity_end("unload_keybag after the copy was not answered status 0");
                };
                let b = self.reply_body(sks::CMD_UNLOAD_KEYBAG, &img);
                if !b.is_empty() && !sks::parse_version(b, 0) {
                    return self.identity_end("unload_keybag's reply is not version 0 alone");
                }
                made = v;
                &made
            }
        };

        // identity_load's tail on the wrapped bag: load, make_system_keybag v1 for the session, unload
        let Some((_, img)) = self.identity_call("7.5 load", sks::CMD_LOAD_KEYBAG, next(), sks::load_keybag(bag)) else {
            return self.identity_end(if kept { "load_keybag of the kept bag was not answered status 0" } else { "load_keybag of the wrapped bag was not answered status 0" });
        };
        let Some(h2) = sks::parse_handle(self.reply_body(sks::CMD_LOAD_KEYBAG, &img)) else {
            return self.identity_end("load_keybag's reply is not {0, handle}");
        };
        let which = if kept { "kept" } else { "new" };
        dev_info!(self.dev, "[sep2] identity: loaded the {} bag, handle {}\n", which, h2);
        self.state_probe("7.5a the session's state", session, next());
        self.state_probe("7.5b the bag's state", h2, next());
        let Some((_, img)) = self.identity_call("7.6 make_system_keybag", sks::CMD_MAKE_SYSTEM_KEYBAG, next(), sks::make_system_keybag(h2, session)) else {
            return self.identity_end("make_system_keybag v1 was not answered status 0");
        };
        let b = self.reply_body(sks::CMD_MAKE_SYSTEM_KEYBAG, &img);
        if !b.is_empty() && !sks::parse_version(b, 1) {
            return self.identity_end("make_system_keybag's reply is not version 1 alone");
        }
        dev_info!(self.dev, "[sep2] identity: designated for session {}\n", session);
        self.state_probe("7.6a the session's state", session, next());
        let Some(_) = self.identity_call("7.7 unload", sks::CMD_UNLOAD_KEYBAG, next(), sks::unload_keybag(h2)) else {
            return self.identity_end("unload_keybag after the designation was not answered status 0");
        };

        // the session unlock as macOS's AKSIdentityUnlockSession makes it: device_state_transition, state 0, with the
        // secret. Its mask's bit 0x20 (the SEP's -30, the kext's 0xe007c01e) is the framework's success too; the
        // session's lock state after it decides.
        let Some((_, img)) = self.identity_call("7.8 unlock", sks::CMD_DEVICE_STATE_TRANSITION, next(), sks::device_state_unlock(session, &id.secret)) else {
            return self.identity_end("device_state_transition to unlocked was not answered status 0");
        };
        let parsed = sks::parse_device_state(self.reply_body(sks::CMD_DEVICE_STATE_TRANSITION, &img));
        let sls = self.state_probe("7.8a the session's state", session, next());
        let Some((mask, time)) = parsed else {
            return self.identity_end("device_state_transition's reply is not {0, lword, lword}");
        };
        let e = sks::state_error(mask).unwrap_or(0);
        dev_info!(self.dev, "[sep2] identity: session {}'s unlock: mask {:#x} (the kext's {:#x}), time {:#x}, lock state {:?}\n", session, mask, e, time, sls);
        if sls != Some(0) {
            return self.identity_end("the session is not unlocked after device_state_transition");
        }
        let mut st = self.state.lock();
        st.sks.next_seq = next();
        st.sks.identity = Some(if kept {
            "the kept bag loaded, designated and unlocked"
        } else {
            "created, copied out, loaded, designated and unlocked"
        });
        true
    }

    // --- stage 8: scrd and sbio ---

    /// Records how stage 8 ended; false, for the caller to return.
    fn sbio_end(&self, why: &'static str) -> bool {
        dev_err!(self.dev, "[sep2] sbio: {}; the step ends, nothing more goes to endpoints {:#04x} and {:#04x}\n", why, proto::EP_SBIO, proto::EP_SCRD);
        self.state.lock().sbio.outcome = Some(why);
        false
    }

    /// One SBIO transaction, a single packet each way: the request in sbio's in buffer and the first packet's word,
    /// then the SEP's one packet from its out buffer (_gt_read_first_packet's checks). None (logged) for no reply, a
    /// reply in more than one packet (its 0xFE is not sent) or one that breaks the checks; an error packet (0xFF)
    /// gives its status (_gt_read_error: header word 4) and no data. Logs the status and length, and the bytes when
    /// `show`.
    /// The request's packet at `off` into sbio's in buffer (proto::gt_packet_at): as much as the buffer takes after
    /// the header (0x3FE4 bytes). The bytes written, or None for no buffer.
    fn sbio_write(&self, op: u8, data: &[u8], off: usize) -> Option<usize> {
        let b = self.bufs.lock();
        let p = b.ool[5].as_ref()?;
        // SAFETY: the SEP reads sbio's in buffer only for a transaction's packet that names it, sent after this write;
        // none is in flight (one at a time: the first packet, or a next one after the SEP's 0xFE for it).
        let buf = unsafe { p.inbound.as_mut() };
        let n = (data.len() - off).min(buf.len() - proto::GT_HEADER);
        proto::gt_packet_at(op, 0, data.len(), off, &data[off..off + n], buf)?;
        Some(n)
    }

    fn sbio_query(&self, op: u8, data: &[u8], show: bool) -> Option<SbioReply> {
        self.sbio_transact(op, data, show, 0)
    }

    /// As sbio_query, and a reply of up to `max_total` bytes may come in more than one packet (0: one only): the
    /// first packet's chunk below its total, then for packet k (from 0) the host's 0xFE with sequence k and nothing
    /// in its buffer, and the SEP's 0xFD with the next chunk at the bytes received so far, until they make the
    /// total; nothing is sent after the last (_gt_read_first_packet 0xfffffe0009d57cf4, _gt_read_next_packet
    /// 0xfffffe0009d5807c, _gt_transfer_reading_complete 0xfffffe0009d5ac40). Each chunk is copied out before the
    /// next request, as the SEP reuses its buffer.
    fn sbio_transact(&self, op: u8, data: &[u8], show: bool, max_total: usize) -> Option<SbioReply> {
        let name = proto::sbio_name(op);
        if let Some(why) = self.state.lock().stopped {
            dev_err!(self.dev, "[sep2] sbio: the xART service stopped at {}: {} is not sent\n", why, name);
            return None;
        }
        let mut off = self.sbio_write(op, data, 0)?;
        let msg = proto::encode_gt_ep(proto::EP_SBIO, op);
        self.state.lock().sbio.sent += 1;
        let mut r = self.app_request_ms(msg, name, SBIO_TIMEOUT_MS)?;
        // a request longer than one packet: the SEP asks for each next one (0xFE), the host writes it at its offset
        // and sends 0xFD with its own sequence, from 1 (gt_handle_generic_transaction 0xfffffe0009d583d8)
        let mut wseq = 1u16;
        while proto::Word::of(&r).tag == proto::GT_MORE {
            let f = proto::Word::of(&r);
            if off >= data.len() || f.op != op || r.msg1 != 0 {
                dev_err!(self.dev, "[sep2] sbio: {}: the SEP asks for a packet the request does not hold (msg0 {:#018x}, {:#x} of {:#x} bytes written); nothing more is sent\n", name, r.msg0, off, data.len());
                return None;
            }
            off += self.sbio_write(op, data, off)?;
            let next = proto::encode_gt_next(proto::EP_SBIO, op, wseq);
            wseq += 1;
            self.state.lock().sbio.sent += 1;
            r = self.app_request_ms(next, "sbio: the request's next packet", SBIO_TIMEOUT_MS)?;
        }
        if off < data.len() && proto::Word::of(&r).tag != proto::GT_ERROR {
            dev_err!(self.dev, "[sep2] sbio: {}: the SEP answered after {:#x} of the request's {:#x} bytes (msg0 {:#018x})\n", name, off, data.len(), r.msg0);
            return None;
        }
        if wseq > 1 {
            dev_info!(self.dev, "[sep2] sbio: {}: the request's {:#x} bytes in {} packets; the reply's sequence {}\n", name, data.len(), wseq, r.msg0 >> 48);
        }
        let f = proto::Word::of(&r);
        barrier::dma_mb(barrier::Read);
        // the header and the data, copied out under the buffers' lock alone
        let mut v = KVec::new();
        let (h, why) = {
            let b = self.bufs.lock();
            let p = b.ool[5].as_ref()?;
            // SAFETY: a read of coherent memory the SEP wrote before its reply; it writes no more until the next
            // request.
            let o = unsafe { p.outbound.as_ref() };
            let w = |i: usize| u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]);
            // version, total, offset, flags, status, opcode, chunk
            let h = [w(0), w(1), w(2), w(3), w(4), w(5), w(6)];
            let room = o.len() - proto::GT_HEADER;
            let why = if f.tag == proto::GT_ERROR {
                None
            } else if f.tag != proto::GT_FIRST || r.msg1 != 0 || ((r.msg0 >> 48) != 0 && wseq == 1) {
                Some("the reply is not a first packet, sequence 0")
            } else if f.op != op || h[5] != u32::from(op) {
                Some("the reply answers another opcode")
            } else if h[0] != 1 || h[2] != 0 || h[6] > h[1] || h[6] as usize > room {
                Some("the reply's header breaks _gt_read_first_packet's checks")
            } else if h[3] & proto::GT_FLAGS_REFUSED != 0 {
                Some("the reply asks for a static, command-specific or no-antireplay buffer, which macOS refuses")
            } else if h[6] != h[1] && (op != proto::SBIO_MULTI_OP || h[1] as usize > max_total) {
                Some("the reply comes in more than one packet")
            } else {
                v.reserve(h[1] as usize, GFP_KERNEL).ok()?;
                v.extend_from_slice(&o[proto::GT_HEADER..proto::GT_HEADER + h[6] as usize], GFP_KERNEL).ok()?;
                None
            };
            (h, why)
        };
        let (flags, status) = (h[3], h[4]);
        if f.tag == proto::GT_ERROR {
            let mut st = self.state.lock();
            st.sbio.replies += 1;
            st.sbio.refused += 1;
            drop(st);
            dev_info!(self.dev, "[sep2] sbio: {}: an error packet (msg0 {:#018x}), status {:#x}\n", name, r.msg0, status);
            let status = if status == 0 { u32::MAX } else { status };
            return Some(SbioReply { status, data: KVec::new() });
        }
        if let Some(why) = why {
            dev_err!(
                self.dev,
                "[sep2] sbio: {}: {} (msg0 {:#018x}; header {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x})\n",
                name, why, r.msg0, h[0], h[1], h[2], h[3], h[4], h[5], h[6]
            );
            return None;
        }
        // the rest of a reply in more than one packet
        let (total, mut seq) = (h[1] as usize, 0u16);
        while v.len() < total {
            let more = proto::encode_gt_more(proto::EP_SBIO, op, seq);
            seq += 1;
            let r = self.app_request_ms(more, "sbio: the next packet", SBIO_TIMEOUT_MS)?;
            let f = proto::Word::of(&r);
            barrier::dma_mb(barrier::Read);
            let b = self.bufs.lock();
            let p = b.ool[5].as_ref()?;
            // SAFETY: a read of coherent memory the SEP wrote before this packet; it writes no more until the next
            // request.
            let o = unsafe { p.outbound.as_ref() };
            let w = |i: usize| u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]);
            let n = [w(0), w(1), w(2), w(3), w(4), w(5), w(6)];
            let room = o.len() - proto::GT_HEADER;
            let why = if f.tag == proto::GT_ERROR {
                Some("an error packet in the middle of the reply")
            } else if f.tag != proto::GT_NEXT || r.msg1 != 0 {
                Some("the packet is not a next packet (0xFD)")
            } else if n[0] != 1 || n[5] != u32::from(op) || n[1] as usize != total {
                Some("the packet's version, op or total differ from the first's")
            } else if n[2] as usize != v.len() || n[6] as usize > room || v.len() + n[6] as usize > total || n[6] == 0 {
                Some("the packet's offset or chunk break _gt_read_next_packet's checks")
            } else {
                None
            };
            if let Some(why) = why {
                drop(b);
                dev_err!(
                    self.dev,
                    "[sep2] sbio: {}: packet {}: {} (msg0 {:#018x}; header {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); nothing more is sent\n",
                    name, seq, why, r.msg0, n[0], n[1], n[2], n[3], n[4], n[5], n[6]
                );
                return None;
            }
            v.extend_from_slice(&o[proto::GT_HEADER..proto::GT_HEADER + n[6] as usize], GFP_KERNEL).ok()?;
        }
        if seq > 0 {
            dev_info!(self.dev, "[sep2] sbio: {}: {:#x} bytes in {} packets\n", name, total, seq + 1);
        }
        {
            let mut st = self.state.lock();
            st.sbio.replies += 1;
            if status != 0 {
                st.sbio.refused += 1;
            }
        }
        if show {
            dev_info!(self.dev, "[sep2] sbio: {}: status {:#x}, flags {:#x}, {:#x} bytes: {}\n", name, status, flags, v.len(), Hex(&v[..v.len().min(0x100)]));
        } else {
            dev_info!(self.dev, "[sep2] sbio: {}: status {:#x}, flags {:#x}, {:#x} bytes\n", name, status, flags, v.len());
        }
        Some(SbioReply { status, data: v })
    }

    /// scrd's INITIALIZE in 27.2's framing (proto::scrd_init_v1): the reply's request, length and status, logged
    /// with what it wrote; true for status 0.
    fn scrd_initialize(&self) -> bool {
        let init = proto::scrd_init_v1();
        {
            let b = self.bufs.lock();
            let Some(p) = &b.ool[4] else {
                return false;
            };
            // SAFETY: the SEP reads scrd's in buffer only for a request that names it, sent after this write.
            let buf = unsafe { p.inbound.as_mut() };
            buf[..init.len()].copy_from_slice(&init);
        }
        let msg = proto::encode_scrd(proto::SCRD_REQ_V1, proto::SCRD_INIT_LEN);
        let Some(r) = self.app_request_ms(msg, "scrd: INITIALIZE, 27.2's framing (request 4)", SCRD_TIMEOUT_MS) else {
            self.state.lock().sbio.scrd = Some("INITIALIZE: no reply");
            return false;
        };
        let m = r.msg0.to_le_bytes();
        let (request, len, status) = (m[1], u16::from_le_bytes([m[2], m[3]]), i32::from_le_bytes([m[4], m[5], m[6], m[7]]));
        barrier::dma_mb(barrier::Read);
        {
            let b = self.bufs.lock();
            if let Some(p) = &b.ool[4] {
                // SAFETY: a read of coherent memory the SEP wrote before its reply, for the log only.
                let o = unsafe { p.outbound.as_ref() };
                let n = usize::from(len).min(0x100);
                dev_info!(self.dev, "[sep2] scrd: INITIALIZE's reply: request {}, {:#x} bytes, status {} (msg1 {:#x}): {}\n", request, len, status, r.msg1, Hex(&o[..n]));
            }
        }
        let ok = status == 0 && request == proto::SCRD_REQ_V1;
        let how = if ok { "INITIALIZE answered status 0" } else { "INITIALIZE not answered request 4, status 0" };
        self.state.lock().sbio.scrd = Some(how);
        ok
    }

    /// Stage 8, after the session's unlock: scrd's and sbio's enables, SBIO's queries that need no sensor, scrd's
    /// INITIALIZE, then the session's state again. A query's refusal is logged and the next one goes; no reply,
    /// or 0x73 refused, ends it.
    fn run_sbio(&self) -> bool {
        if !self.check_apps(&[App::Scrd, App::Sbio]) {
            return self.sbio_end("scrd or sbio is not as on 14.8.3, so not enabled");
        }
        if !self.run_steps("scrd, sbio", &proto::STAGE8) {
            return self.sbio_end("the enables stopped");
        }
        let uid = self.identity.as_ref().map_or(1000, |id| id.uid as i32);
        let Some(r) = self.sbio_query(0x73, &proto::SBIO_GENERATION.to_le_bytes(), true) else {
            return self.sbio_end("0x73 was not answered in one packet");
        };
        if r.status != 0 {
            return self.sbio_end("0x73 {8}, 27.2's communication init, was refused");
        }
        for op in [0x7c, 0x40, 0x6b, 0x79] {
            if self.sbio_query(op, &[], true).is_none() {
                return self.sbio_end("a query was not answered in one packet");
            }
        }
        // 0x7a: 40-byte records {i32 uid, the UUID (16), ...}: the count, and each record without its UUID
        let Some(r) = self.sbio_query(0x7a, &[], false) else {
            return self.sbio_end("0x7a was not answered in one packet");
        };
        if r.status == 0 {
            dev_info!(self.dev, "[sep2] sbio: {} identity records, {:#x} bytes over\n", r.data.len() / 40, r.data.len() % 40);
            for rec in r.data.chunks_exact(40) {
                let u = i32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                dev_info!(self.dev, "[sep2] sbio:   uid {}, then {}\n", u, Hex(&rec[20..]));
            }
        }
        // 0x38 v2: {uid, 1 (built-in), 16 zeros}
        let mut v2 = [0u8; 24];
        v2[..4].copy_from_slice(&uid.to_le_bytes());
        v2[4..8].copy_from_slice(&1u32.to_le_bytes());
        if self.sbio_query(0x38, &v2, true).is_none() || self.sbio_query(0x39, &[], true).is_none() {
            return self.sbio_end("0x38 or 0x39 was not answered in one packet");
        }
        // 0x33: each catacomb's ID, compared with the .gl copy's lockers, never logged
        for who in [-1i32, 501, uid] {
            let Some(r) = self.sbio_query(0x33, &who.to_le_bytes(), false) else {
                return self.sbio_end("0x33 was not answered in one packet");
            };
            let Ok(id) = <[u8; 16]>::try_from(r.data.get(..16).unwrap_or(&[])) else {
                continue;
            };
            let store = self.xart.lock();
            let found = store.as_ref().and_then(|s| {
                [xart::TYPE_SESSION_USER, xart::TYPE_SESSION_SEP]
                    .into_iter()
                    .find(|&ty| s.slot_of(&xart::session_key(ty, &id)).is_some())
            });
            drop(store);
            let zero = id.iter().all(|&c| c == 0);
            match found {
                Some(ty) => dev_info!(self.dev, "[sep2] sbio: uid {}'s catacomb ID is a locker's in the .gl copy (type {})\n", who, ty),
                None => dev_info!(self.dev, "[sep2] sbio: uid {}'s catacomb ID matches no locker (all zero: {})\n", who, zero),
            }
        }
        for op in [0x2b, 0x2e, 0x36] {
            if self.sbio_query(op, &uid.to_le_bytes(), true).is_none() {
                return self.sbio_end("a per-uid query was not answered in one packet");
            }
        }
        for op in [0x63, 0x1f] {
            if self.sbio_query(op, &[], true).is_none() {
                return self.sbio_end("a calibration or policy query was not answered in one packet");
            }
        }
        let scrd = self.scrd_initialize();
        let seq = self.state.lock().sks.next_seq;
        let session = -uid;
        let sls = self.state_probe("8 the session's state", session, seq);
        let taken = if scrd { "taken" } else { "not taken" };
        dev_info!(self.dev, "[sep2] sbio: done; scrd INITIALIZE {}; the session's lock state {:?}\n", taken, sls);
        self.state.lock().sbio.outcome = Some("the queries answered");
        true
    }

    // --- stage 10: the enrolment's credential ---

    /// Records how stage 10 ended; false, for the caller to return.
    fn cred_end(&self, why: &'static str) -> bool {
        dev_err!(self.dev, "[sep2] credential: {}; the step ends\n", why);
        self.state.lock().sbio.cred = Some(why);
        false
    }

    /// One ACM command on scrd in 27.2's framing (proto::scrd_cred_request), waiting up to 5 s as sendSEPCommand: the
    /// reply's status and the command's output after the response head, or None (logged) for no reply, or one that
    /// breaks sendSEPCommand's checks (another request, a head shorter than 0xc bytes, version 0, another request ID,
    /// a head longer than the reply). The output is shown when `show`.
    fn scrd_command(&self, what: &str, cmd: u8, data: &[u8], show: bool) -> Option<(i32, KVec<u8>)> {
        if let Some(why) = self.state.lock().stopped {
            dev_err!(self.dev, "[sep2] credential: the xART service stopped at {}: {} is not sent\n", why, what);
            return None;
        }
        let id = {
            let mut st = self.state.lock();
            st.sbio.scrd_id = st.sbio.scrd_id.wrapping_add(1).max(2);
            st.sbio.scrd_id
        };
        let len = {
            let b = self.bufs.lock();
            let p = b.ool[4].as_ref()?;
            // SAFETY: the SEP reads scrd's in buffer only for a request that names it, sent after this write, and
            // writes its out buffer only for a reply; none is in flight (one at a time, the last one answered).
            let n = unsafe {
                p.outbound.as_mut().fill(0);
                proto::scrd_cred_request(id, cmd, data, p.inbound.as_mut())
            };
            let Some(n) = n else {
                dev_err!(self.dev, "[sep2] credential: {}: not a stage-10 request\n", what);
                return None;
            };
            n
        };
        let r = self.app_request_ms(proto::encode_scrd(proto::SCRD_REQ_V1, len as u16), what, SCRD_TIMEOUT_MS)?;
        let m = r.msg0.to_le_bytes();
        let (request, rlen) = (m[1], usize::from(u16::from_le_bytes([m[2], m[3]])));
        let status = i32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        barrier::dma_mb(barrier::Read);
        let b = self.bufs.lock();
        let p = b.ool[4].as_ref()?;
        // SAFETY: a read of coherent memory the SEP wrote before its reply; it writes no more until the next request.
        let o = unsafe { p.outbound.as_ref() };
        let head = if rlen >= proto::SCRD_REPLY_HEAD_MIN && rlen <= o.len() {
            usize::from(u16::from_le_bytes([o[2], o[3]]))
        } else {
            0
        };
        let why = if request != proto::SCRD_REQ_V1 || r.msg1 != 0 {
            Some("the reply is not request 4's")
        } else if rlen > o.len() {
            Some("the reply is longer than scrd's buffer")
        } else if rlen < proto::SCRD_REPLY_HEAD_MIN {
            Some("the reply has no response head")
        } else if o[0] == 0 {
            Some("the response head's version is 0")
        } else if u32::from_le_bytes([o[4], o[5], o[6], o[7]]) != id {
            Some("the response head names another request")
        } else if head < proto::SCRD_REPLY_HEAD_MIN || head > rlen {
            Some("the response head's length is outside the reply")
        } else {
            None
        };
        if let Some(why) = why {
            let n = rlen.min(o.len()).min(0x40);
            dev_err!(self.dev, "[sep2] credential: {}: {} (msg0 {:#018x}, status {}): {}\n", what, why, r.msg0, status, Hex(&o[..n]));
            return None;
        }
        let out = &o[head..rlen];
        if show {
            dev_info!(self.dev, "[sep2] credential: {}: request {}, status {}, head v{} {:#x} bytes, output {:#x} bytes: {}\n", what, id, status, o[0], head, out.len(), Hex(&out[..out.len().min(0x80)]));
        } else {
            dev_info!(self.dev, "[sep2] credential: {}: request {}, status {}, head v{} {:#x} bytes, output {:#x} bytes\n", what, id, status, o[0], head, out.len());
        }
        let mut v = KVec::new();
        v.extend_from_slice(out, GFP_KERNEL).ok()?;
        Some((status, v))
    }

    /// The kept bag's secret verified into the context `acm`, as 27.2's identity_verify: load the wrapped bag,
    /// verify_secret v1 with the loaded handle, unload it whatever the verify answered. The action mask, or why not.
    fn cred_verify(&self, bag: &[u8], secret: &[u8], acm: &[u8; proto::ACM_HANDLE_LEN], seq: &mut u8) -> core::result::Result<u64, &'static str> {
        let mut next = || {
            *seq = seq.wrapping_add(1);
            *seq
        };
        let Some((_, img)) = self.identity_call("10.3 load", sks::CMD_LOAD_KEYBAG, next(), sks::load_keybag(bag)) else {
            return Err("load_keybag of the kept bag was not answered status 0");
        };
        let Some(h) = sks::parse_handle(self.reply_body(sks::CMD_LOAD_KEYBAG, &img)) else {
            return Err("load_keybag's reply is not {0, handle}");
        };
        dev_info!(self.dev, "[sep2] credential: the kept bag loaded, handle {}\n", h);
        let verified = self
            .identity_call("10.4 verify_secret", sks::CMD_VERIFY_SECRET, next(), sks::verify_secret(h, secret, acm))
            .map(|(_, img)| sks::parse_verify(self.reply_body(sks::CMD_VERIFY_SECRET, &img)));
        let unloaded = self.identity_call("10.5 unload", sks::CMD_UNLOAD_KEYBAG, next(), sks::unload_keybag(h)).is_some();
        let mask = match verified {
            None => return Err("verify_secret was not answered status 0"),
            Some(None) => return Err("verify_secret's reply is not {1, mask}"),
            Some(Some(m)) => m,
        };
        if !unloaded {
            return Err("unload_keybag after the verify was not answered status 0");
        }
        Ok(mask)
    }

    /// The kept wrapped bag: the identity file's, else the one stage 7 made on this boot.
    fn kept_bag(&self, id: &Identity) -> Option<KVec<u8>> {
        let mut bag = KVec::new();
        let kept = match (id.bag.as_deref(), self.bag_file.as_ref()) {
            (Some(b), _) => bag.extend_from_slice(b, GFP_KERNEL).is_ok(),
            (None, Some(f)) => {
                let made = f.lock();
                !made.is_empty() && bag.extend_from_slice(&made, GFP_KERNEL).is_ok()
            }
            (None, None) => false,
        };
        kept.then_some(bag)
    }

    /// The credential BEGIN_ENROL carries (step 10b), left open: an ACM context for the identity file's uid,
    /// externalized; the kept bag's secret verified into it; the policy "TouchIdEnrollment" checked in it
    /// (satisfied: the output's first u32, bit 0). The context's handle, or why not, with the context deleted.
    fn cred_open(&self) -> core::result::Result<[u8; proto::ACM_HANDLE_LEN], &'static str> {
        let Some(id) = self.identity.as_ref() else {
            return Err("no identity file");
        };
        let Some(bag) = self.kept_bag(id) else {
            return Err("no wrapped bag, kept or made at stage 7");
        };
        let uid = id.uid;
        let Some((status, out)) = self.scrd_command("10.1 ContextCreateWithTracking", proto::SCRD_CMD_CONTEXT_CREATE_TRACKED, &uid.to_le_bytes(), false) else {
            return Err("the context create was not answered");
        };
        if status != 0 || out.len() < proto::ACM_HANDLE_LEN {
            return Err("the context create was not answered status 0 with a handle");
        }
        let mut acm = [0u8; proto::ACM_HANDLE_LEN];
        acm.copy_from_slice(&out[..proto::ACM_HANDLE_LEN]);
        if out.len() >= 0x15 {
            let tracking = u32::from_le_bytes([out[0x11], out[0x12], out[0x13], out[0x14]]);
            dev_info!(self.dev, "[sep2] credential: a context for uid {}, tracking number {}, the SEP's log level {:#x}\n", uid, tracking, out[0x10]);
        }
        let mut seq = self.state.lock().sks.next_seq;
        let outcome: core::result::Result<(), &'static str> = 'chain: {
            match self.scrd_command("10.2 ExternalizeContext", proto::SCRD_CMD_EXTERNALIZE, &acm, true) {
                Some((0, _)) => {}
                Some(_) => break 'chain Err("the externalize was not answered status 0"),
                None => break 'chain Err("the externalize was not answered"),
            }
            match self.cred_verify(&bag, &id.secret, &acm, &mut seq) {
                Ok(mask) => {
                    let e = sks::state_error(mask).unwrap_or(0);
                    dev_info!(self.dev, "[sep2] credential: verify_secret's action mask {:#x} (the kext's {:#x})\n", mask, e);
                }
                Err(why) => break 'chain Err(why),
            }
            let data = proto::scrd_policy_data(&acm);
            let Some((status, out)) = self.scrd_command("10.6 VerifyPolicy TouchIdEnrollment", proto::SCRD_CMD_VERIFY_POLICY, &data, true) else {
                break 'chain Err("the policy check was not answered");
            };
            if status != 0 || out.len() < 4 {
                break 'chain Err("the policy check was not answered status 0 with a result");
            }
            let satisfied = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) & 1 != 0;
            dev_info!(self.dev, "[sep2] credential: TouchIdEnrollment {}, a requirement of {:#x} bytes\n", if satisfied { "satisfied" } else { "NOT satisfied" }, out.len() - 4);
            if satisfied {
                Ok(())
            } else {
                Err("TouchIdEnrollment not satisfied")
            }
        };
        self.state.lock().sks.next_seq = seq.wrapping_add(1);
        match outcome {
            Ok(()) => Ok(acm),
            Err(why) => {
                self.cred_close(&acm, uid);
                Err(why)
            }
        }
    }

    /// The context deleted, then the session's state; true if the delete was answered status 0.
    fn cred_close(&self, acm: &[u8; proto::ACM_HANDLE_LEN], uid: u32) -> bool {
        let deleted = matches!(self.scrd_command("10.7 ContextDelete", proto::SCRD_CMD_CONTEXT_DELETE, acm, false), Some((0, _)));
        let seq = self.state.lock().sks.next_seq;
        let sls = self.state_probe("10.8 the session's state", -(uid as i32), seq);
        self.state.lock().sks.next_seq = seq.wrapping_add(1);
        dev_info!(self.dev, "[sep2] credential: the context {}; the session's lock state {:?}\n", if deleted { "deleted" } else { "NOT deleted" }, sls);
        deleted
    }

    /// Stage 10, after stage 9: the credential opened (cred_open) and closed, the session's state last. No
    /// enrolment is begun.
    fn run_credential(&self) -> bool {
        let uid = match self.identity.as_ref() {
            Some(id) => id.uid,
            None => return self.cred_end("no identity file"),
        };
        match self.cred_open() {
            Ok(acm) => {
                if self.cred_close(&acm, uid) {
                    self.state.lock().sbio.cred = Some("TouchIdEnrollment satisfied");
                    true
                } else {
                    self.cred_end("TouchIdEnrollment satisfied, the context's delete not answered status 0")
                }
            }
            Err(why) => self.cred_end(why),
        }
    }

    // --- stage 11: the capture alone ---

    /// Stage 11 (Touch ID step 10a), after the bring-up and before the power goes off, nothing to the SEP: one capture
    /// (capture_once), then Idle and the status. The shim's capture frames are armed only meanwhile.
    fn run_capture(&self) -> &'static str {
        if mesa::capture_arm(true).is_err() {
            return "the capture's frames could not be armed";
        }
        let how = self.capture_once();
        let idle = mesa::command(mesa::T_IDLE).is_ok();
        match mesa::status() {
            Ok(s) => self.mesa_log(if idle { "after Idle" } else { "Idle not sent" }, &s),
            Err(_) => dev_err!(self.dev, "[sep2] capture: no status after Idle\n"),
        }
        let _ = mesa::capture_arm(false);
        how
    }

    /// Stage 11's capture: one image (capture_image), checked (capture_check), never relayed (no SBIO 0x65).
    fn capture_once(&self) -> &'static str {
        match self.capture_image(CAPTURE_MS) {
            Ok((img, ready, at)) => self.capture_check(img, ready, at),
            Err(why) => why,
        }
    }

    /// StartCapture (80 40, from idle, as `_handleCMD` case 6), then the status every 10 ms for up to `window` ms
    /// while a finger is placed: each change of state or of [11] logged with the time since StartCapture; in state 7
    /// with 0x7200 bytes ready (else 0x4800, as handleStateMachine) the image read once. The image, the bytes ready
    /// and the time, or why not. Stops at an SPI error, a reset or recovery event, state 9, or the window's end.
    fn capture_image(&self, window: u32) -> core::result::Result<(KVec<u8>, u32, u32), &'static str> {
        let s = mesa::status().map_err(|_| "GetStatus failed before StartCapture")?;
        self.mesa_log("before StartCapture", &s);
        if !s.sane() || s.state() != mesa::STATE_IDLE {
            return Err("the sensor is not sane and idle before StartCapture");
        }
        mesa::command(mesa::T_START_CAPTURE).map_err(|_| "StartCapture was not sent")?;
        dev_info!(self.dev, "[sep2] capture: StartCapture sent; a finger on the sensor within {} s\n", window / 1000);
        let mut last: Option<(u8, u8)> = None;
        let mut waited = 0u32;
        loop {
            let s = mesa::status().map_err(|_| "a status read failed during the capture")?;
            if last != Some((s.state(), s.0[11])) {
                last = Some((s.state(), s.0[11]));
                dev_info!(self.dev, "[sep2] capture: at {} ms: {} (state {} {}, [11] {:#04x}, ready {:#x})\n", waited, Hex(&s.0), s.state(), mesa::state_name(s.state()), s.0[11], s.count());
            }
            if s.spi_error() {
                return Err("an SPI error ([11] bit 0) during the capture");
            }
            if s.event() && matches!(s.code(), 0x10 | 0x20 | 0x30 | 0x40) {
                return Err("a reset or recovery event during the capture");
            }
            match s.state() {
                mesa::STATE_NEEDS_PATCH => return Err("state 9: the sensor wants its patch again"),
                mesa::STATE_DATA_READY if s.count() as usize >= mesa::IMAGE_LEN_SHORT => {
                    let n = if s.count() as usize >= mesa::IMAGE_LEN { mesa::IMAGE_LEN } else { mesa::IMAGE_LEN_SHORT };
                    let img = mesa::read_image(n).map_err(|_| "the image read failed")?;
                    return Ok((img, s.count(), waited));
                }
                mesa::STATE_DATA_READY => return Err("data ready with less than 0x4800 bytes"),
                _ => {}
            }
            if waited >= window {
                return Err("no image within the window");
            }
            if !self.nap(CAPTURE_POLL_MS) {
                return Err("the driver is going away");
            }
            waited += CAPTURE_POLL_MS;
        }
    }

    /// The image's checks as macOS (12 slices, each its length and CRC-16) and with one CRC-16 over the whole read,
    /// logged; the slices' headers logged when `headers`, nothing else.
    fn image_check_log(&self, img: &[u8], ready: u32, at: u32, headers: bool) -> mesa::ImageCheck {
        let n = img.len();
        let c = mesa::check_image(img);
        let per = n / mesa::IMAGE_SLICES;
        for i in (0..mesa::IMAGE_SLICES).filter(|_| headers) {
            dev_info!(self.dev, "[sep2] capture: slice {} header {}\n", i, Hex(&img[i * per..i * per + 7]));
        }
        dev_info!(
            self.dev,
            "[sep2] capture: an image of {:#x} bytes ({:#x} ready) at {} ms: {} of 12 slices' lengths and {} CRCs good (first bad {:?}); one CRC over the whole read {}\n",
            n, ready, at, c.lengths_ok, c.crcs_ok, c.first_bad, if c.whole_crc_ok { "good" } else { "bad" }
        );
        c
    }

    /// Stage 11's checks (image_check_log), the image zeroed after them, never kept.
    fn capture_check(&self, mut img: KVec<u8>, ready: u32, at: u32) -> &'static str {
        let c = self.image_check_log(&img, ready, at, true);
        img.fill(0);
        drop(img);
        match mesa::status() {
            Ok(s) => self.mesa_log("after the read", &s),
            Err(_) => return "no status after the image read",
        }
        if c.crcs_ok == mesa::IMAGE_SLICES {
            "one image read, its 12 slices' CRCs good (macOS's rule)"
        } else if c.whole_crc_ok {
            "one image read, one CRC over the whole read good, the slices' not"
        } else {
            "one image read, neither CRC rule holds"
        }
    }

    // --- stage 12: an enrolment, cancelled before its save ---

    /// One stage-12 SBIO op whose reply must be status 0; its data, or None (logged).
    fn enrol_sbio(&self, op: u8, data: &[u8], show: bool) -> Option<KVec<u8>> {
        let r = self.sbio_query(op, data, show)?;
        if r.status != 0 {
            dev_err!(self.dev, "[sep2] enrol: {}: status {:#x}, not 0\n", proto::sbio_name(op), r.status);
            return None;
        }
        Some(r.data)
    }

    /// Stage 12 (Touch ID step 10c), after the bring-up and before the power goes off: an enrolment as 27.2 runs one,
    /// cancelled before any save; the SEP's xART writes held as at stage 7, so a write request ends it.
    /// 1. the context: 0x2d for the system (−1; with no catacomb loaded, as stage 8's 0x7a showed no identity),
    ///    0x6b (each component's state logged; the master's must be active), 0x2d and 0x2b for the user;
    /// 2. the credential (cred_open), kept open;
    /// 3. BEGIN_ENROL 0x03 and the images (enrol_images);
    /// 4. the cancel 0x05 once BEGIN_ENROL took (commandCancel in mode 3), Idle, the credential closed.
    fn run_enrol(&self) -> &'static str {
        let uid = match self.identity.as_ref() {
            Some(id) => id.uid,
            None => return "no identity file",
        };
        let user = uid as i32;
        if self.enrol_sbio(proto::SBIO_SELECT_CONTEXT, &proto::USER_SYSTEM.to_le_bytes(), true).is_none() {
            return "0x2d for the system context was not answered status 0";
        }
        let Some(states) = self.enrol_sbio(0x6b, &[], true) else {
            return "0x6b after the system context was not answered status 0";
        };
        let mut master = None;
        for c in states.chunks_exact(8) {
            let who = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            let st = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            dev_info!(self.dev, "[sep2] enrol: component {}: state {:#x}\n", who, st);
            if who == proto::USER_SYSTEM {
                master = Some(st);
            }
        }
        if master.is_none_or(|st| st & 2 == 0) {
            return "the master component is not active after the system context";
        }
        if self.enrol_sbio(proto::SBIO_SELECT_CONTEXT, &user.to_le_bytes(), true).is_none() {
            return "0x2d for the user was not answered status 0";
        }
        if self.enrol_sbio(proto::SBIO_PROTECTED_CONFIG, &user.to_le_bytes(), true).is_none() {
            return "0x2b for the user was not answered status 0";
        }
        let acm = match self.cred_open() {
            Ok(a) => a,
            Err(why) => return why,
        };
        if mesa::capture_arm(true).is_err() {
            self.cred_close(&acm, uid);
            return "the capture's frames could not be armed";
        }
        let (how, begun) = self.enrol_images(uid, &acm);
        if begun {
            let cancelled = self.enrol_sbio(proto::SBIO_CANCEL, &[], true).is_some();
            dev_info!(self.dev, "[sep2] enrol: the cancel {}\n", if cancelled { "answered status 0" } else { "NOT answered status 0" });
        }
        let idle = mesa::command(mesa::T_IDLE).is_ok();
        match mesa::status() {
            Ok(s) => self.mesa_log(if idle { "after Idle" } else { "Idle not sent" }, &s),
            Err(_) => dev_err!(self.dev, "[sep2] enrol: no status after Idle\n"),
        }
        let _ = mesa::capture_arm(false);
        self.cred_close(&acm, uid);
        how
    }

    /// BEGIN_ENROL with the open credential, then up to ENROL_IMAGES images, each a touch of its own (one capture,
    /// Idle, ENROL_LIFT_MS for the finger to lift and come back): the image read (exactly 0x7200 bytes, the
    /// SEP's capture buffer for the sensor type 3), then 0x23, 0x06, 0x65 (the image, in two packets), 0x07; 0x08
    /// when 0x07 says the image is usable for the enrolment; 0x22. Ends at 0x08's done flag, an enrolment error
    /// without a placement, or any refusal. How it ended, and whether BEGIN_ENROL took.
    fn enrol_images(&self, uid: u32, acm: &[u8; proto::ACM_HANDLE_LEN]) -> (&'static str, bool) {
        if self.enrol_sbio(proto::SBIO_BEGIN_ENROL, &proto::begin_enrol(uid, acm), true).is_none() {
            return ("BEGIN_ENROL was not answered status 0", false);
        }
        dev_info!(self.dev, "[sep2] enrol: BEGIN_ENROL took; up to {} images, a finger on the sensor for each\n", ENROL_IMAGES);
        let mut used = 0u32;
        for i in 0..ENROL_IMAGES {
            let (mut img, ready, at) = match self.capture_image(ENROL_CAPTURE_MS) {
                Ok(v) => v,
                Err(why) => return (why, true),
            };
            let ticks = mesa::ticks();
            self.image_check_log(&img, ready, at, i == 0);
            let step = self.enrol_relay(i, &img, ticks);
            img.fill(0);
            drop(img);
            match step {
                Relay::Next(took) => used += took as u32,
                Relay::Done(how) => {
                    dev_info!(self.dev, "[sep2] enrol: {} images, {} used\n", i + 1, used);
                    return (how, true);
                }
            }
            if mesa::command(mesa::T_IDLE).is_err() {
                return ("Idle after an image was not sent", true);
            }
            if !self.nap(ENROL_LIFT_MS) {
                return ("the driver is going away", true);
            }
        }
        dev_info!(self.dev, "[sep2] enrol: {} images, {} used\n", ENROL_IMAGES, used);
        ("the image limit reached before the done flag", true)
    }

    /// One image relayed as asyncCaptureHandler relays it; what came of it.
    fn enrol_relay(&self, i: u32, img: &[u8], ticks: u64) -> Relay {
        if img.len() != mesa::IMAGE_LEN {
            return Relay::Done("an image of 0x4800 bytes: the SEP's capture buffer for this sensor is 0x7200");
        }
        if self.enrol_sbio(proto::SBIO_IMAGE_PREPARE, &[], false).is_none() {
            return Relay::Done("0x23 was not answered status 0");
        }
        if self.enrol_sbio(proto::SBIO_IMAGE_INIT, &proto::image_init(0, ticks), false).is_none() {
            return Relay::Done("0x06 was not answered status 0");
        }
        if self.enrol_sbio(proto::SBIO_CAPTURE, img, false).is_none() {
            return Relay::Done("0x65 (the image) was not answered status 0");
        }
        let Some(a) = self.enrol_sbio(proto::SBIO_IMAGE_ASSESS, &[], false) else {
            return Relay::Done("0x07 was not answered status 0");
        };
        let Some(a) = proto::parse_assessment(&a) else {
            return Relay::Done("0x07's reply is shorter than 0x89 bytes and its extension");
        };
        dev_info!(
            self.dev,
            "[sep2] enrol: image {}: error {}, for the enrolment {}, for a match {}, assessment {}, feedback {}, purpose {}, outliers {}, dirt {}\n",
            i, a.err, a.for_enrol, a.for_match, a.assessment, a.feedback, a.purpose, a.outliers, a.dirt
        );
        let mut end = None;
        if a.for_enrol != 0 {
            match self.enrol_sbio(proto::SBIO_ENROL_RESULT, &[], false).map(|v| proto::parse_enrol_result(&v)) {
                None => end = Some("0x08 was not answered status 0"),
                Some(None) => end = Some("0x08's reply is not 0xc98 bytes"),
                Some(Some(r)) => {
                    let (placed, identity, user) = (r.placement != 0, r.identity != 0, r.user as i32);
                    dev_info!(
                        self.dev,
                        "[sep2] enrol: image {}: done {}, error {:#x}, progress {}, placement {}, identity {} (user {})\n",
                        i, r.done, r.err, r.progress, placed, identity, user
                    );
                    if r.done != 0 || r.err == proto::ENROL_ERR_END {
                        end = Some(if r.err == 0 { "the enrolment complete (0x08's done flag), cancelled before its save" } else { "the enrolment ended with an error" });
                    } else if r.err != 0 && r.placement == 0 {
                        end = Some("an enrolment error without a placement (the kext stops the enrolment)");
                    }
                }
            }
        }
        if self.enrol_sbio(proto::SBIO_BG_OPS, &[], false).is_none() {
            return Relay::Done(end.unwrap_or("0x22 was not answered status 0"));
        }
        match end {
            Some(how) => Relay::Done(how),
            None => Relay::Next(a.for_enrol != 0),
        }
    }

    // --- stage 9: the sensor ---

    /// Records how stage 9 ended, with the sensor's power off; false, for the caller to return.
    fn mesa_end(&self, why: &'static str) -> bool {
        let off = mesa::power(false).is_ok();
        dev_err!(self.dev, "[sep2] mesa: {}; the step ends, the power {}\n", why, if off { "off" } else { "not switched" });
        self.state.lock().sbio.mesa = Some(why);
        false
    }

    /// Logs one status read.
    fn mesa_log(&self, what: &str, s: &mesa::Status) {
        dev_info!(
            self.dev,
            "[sep2] mesa: {}: {} (sane {}, state {}, result {:#04x}, provision {:#04x}, [12..15] {:#x})\n",
            what, Hex(&s.0), s.sane(), s.state(), s.result(), s.provision(), s.count()
        );
    }

    /// The sensor's event after a frame, polled as macOS's 500 ms timer and interrupt would see it, and logged; None
    /// (logged) for a fault, no event, or a failed read.
    fn mesa_event(&self, what: &str, first_ms: u32, every_ms: u32, ms: u32, reset_ok: bool) -> Option<mesa::Status> {
        match mesa::wait_event(first_ms, every_ms, ms, reset_ok) {
            Ok(mesa::Event::Seen(s)) => {
                self.mesa_log(what, &s);
                Some(s)
            }
            Ok(mesa::Event::Fault(s, why)) => {
                self.mesa_log(what, &s);
                dev_err!(self.dev, "[sep2] mesa: {}: {}\n", what, why);
                None
            }
            Ok(mesa::Event::Timeout(s)) => {
                self.mesa_log(what, &s);
                dev_err!(self.dev, "[sep2] mesa: {}: no event within {} ms\n", what, ms);
                None
            }
            Err(e) => {
                dev_err!(self.dev, "[sep2] mesa: {}: the status read failed: {:?}\n", what, e);
                None
            }
        }
    }

    /// READ(n), n one of `ok`: an event in state 7 with n ready, the read, the status again. The sensor's error reply
    /// (0x0B bytes) is read and logged, and gives None, as does anything else. The bytes are not logged: they hold
    /// serial numbers and session material.
    fn mesa_read(&self, what: &'static str, ok: &[u32]) -> Option<KVec<u8>> {
        let s = self.mesa_event(what, 0, 5, mesa::STEP_MS, false)?;
        let n = s.count();
        if s.state() != mesa::STATE_DATA_READY || !(ok.contains(&n) || n == mesa::ERROR_REPLY) {
            dev_err!(self.dev, "[sep2] mesa: {}: state {}, {:#x} bytes ready, not state 7 with {:x?}\n", what, s.state(), n, ok);
            return None;
        }
        let v = match mesa::read(n as usize) {
            Ok(v) => v,
            Err(e) => {
                dev_err!(self.dev, "[sep2] mesa: {}: the read failed: {:?}\n", what, e);
                return None;
            }
        };
        if let Ok(s) = mesa::status() {
            self.mesa_log("the status after the read", &s);
        }
        if n == mesa::ERROR_REPLY {
            dev_err!(self.dev, "[sep2] mesa: {}: the sensor's error reply: {}\n", what, Hex(&v));
            return None;
        }
        dev_info!(self.dev, "[sep2] mesa: {}: {:#x} bytes read\n", what, n);
        Some(v)
    }

    /// One SBIO op of the bring-up whose reply must be status 0 and, when `len` is Some, exactly that long; None
    /// (logged) otherwise. Its bytes are logged only when `show`.
    fn mesa_sbio(&self, op: u8, data: &[u8], len: Option<usize>, show: bool) -> Option<SbioReply> {
        let r = self.sbio_query(op, data, show)?;
        if r.status != 0 || len.is_some_and(|n| r.data.len() != n) {
            dev_err!(self.dev, "[sep2] mesa: {}: status {:#x}, {:#x} bytes, not status 0 with {:?}\n", proto::sbio_name(op), r.status, r.data.len(), len);
            return None;
        }
        Some(r)
    }

    /// One encrypted parameter blob (0x5D's, 0x5C's) as SetEncryptedParameters: the 0x40-byte frame with 0x50 at 0x27
    /// (AppleSandDollar::tryFillSetParamBuffer 0xfffffe000920e538), one 0x40-byte transfer, then the event, [8] 0x29
    /// or 0. Or 0x6A's: the 0x4D-byte frame in a 0x12B-byte transfer (_sendEncryptedCommand 0xfffffe0009203dc8).
    fn mesa_param(&self, op: u8, blob: &[u8]) -> bool {
        let (len, xfer, fill, max): (usize, usize, &[(usize, u8)], usize) =
            if op == 0x6a { (0x4d, mesa::ENC_XFER, &[], 0x44) } else { (0x40, 0x40, &[(0x27, 0x50)], 0x37) };
        if blob.is_empty() || blob.len() > max {
            dev_err!(self.dev, "[sep2] mesa: {}'s blob is {:#x} bytes, not 1-{:#x}\n", proto::sbio_name(op), blob.len(), max);
            return false;
        }
        if let Err(e) = mesa::send_encrypted(blob, len, xfer, fill) {
            dev_err!(self.dev, "[sep2] mesa: {}'s frame was not sent: {:?}\n", proto::sbio_name(op), e);
            return false;
        }
        let Some(s) = self.mesa_event("the parameters' status", 0, 5, mesa::STEP_MS, false) else {
            return false;
        };
        if !matches!(s.result(), mesa::RESULT_DONE | 0) {
            dev_err!(self.dev, "[sep2] mesa: {}: result {:#04x}, not 0x29 or 0\n", proto::sbio_name(op), s.result());
            return false;
        }
        true
    }

    /// Stage 9 after stage 8: the sensor's bring-up as 27.2's AppleMesaSEPDriver runs it (resetSensorAndLoadPatch
    /// 0xfffffe0009abcb18; work/scratch/agents/sep-step9-relay.md sec. 1), each SBIO op's answer relayed to the sensor
    /// in that op's frame and the sensor's answer back, stopping at the first surprise with the power off:
    /// 1. the power cycle and its reset event; the sensor's ID 0x3352, provisioned (0x20); SBIO 0x80 {the ID};
    /// 2. GetSerialNumber, READ(0x1B), SBIO 0x17 {the serial at 9};
    /// 3. SBIO 0x15 {1} (0x28 bytes) as the 0x72 frame, READ(0x33), SBIO 0x16 {40 at 9};
    /// 4. SBIO 0x42 (0x40 bytes) as the 0x73 frame, READ(0x4B), SBIO 0x18 {64 at 9};
    /// 5. SBIO 0x5F {2} (the patch, in packets), SetupPatchEnable and its event in state 0, the patch raw, its event
    ///    with [8] 0x29;
    /// 6. SBIO 0x5D {0} and 0x5C {8 zeros}, each blob a set-parameter frame; SBIO 0x6A, its blob if any;
    /// 7. a status read; SBIO 0x31 (0x40 bytes) as the module serial number's frame, READ(0x4B or 0x4F), its CRC
    ///    checked, SBIO 0x32 {the payload} (18 bytes);
    /// 8. SBIO 0x01 and 0x1F.
    fn run_mesa(&self) -> bool {
        if !mesa::present() {
            return self.mesa_end("no sensor bound (spi2-on.ko power=1 first)");
        }
        // 1. resetSensor's Reset(2) (ResetGated 0xfffffe000920713c → powerOnReset): off 10 ms, on 7 ms, the reset's event
        if mesa::power(false).is_err() || mesa::power(true).is_err() {
            return self.mesa_end("the power cycle failed");
        }
        let Some(s) = self.mesa_event("the reset's status", 0, 5, mesa::STEP_MS, true) else {
            return self.mesa_end("no reset event after the power cycle");
        };
        if !s.sane() || s.state() != mesa::STATE_IDLE || s.id() != mesa::SENSOR_ID {
            return self.mesa_end("the status after the reset is not a sane state 0 with the ID 0x3352");
        }
        if matches!(s.result(), 0x00 | 0x29 | 0x3d) || s.provision() != mesa::PROVISIONED {
            return self.mesa_end("the sensor is not provisioned as resetSensor wants it (a hard stop)");
        }
        if self.mesa_sbio(0x80, &mesa::SENSOR_ID.to_le_bytes(), None, true).is_none() {
            return self.mesa_end("SBIO 0x80 was not answered status 0");
        }

        // 2. syncSensorIdentifiersWithSep (0xfffffe0009abe56c): the serial number, unchecked as macOS leaves it
        if mesa::command(mesa::T_SERIAL).is_err() {
            return self.mesa_end("GetSerialNumber was not sent");
        }
        let Some(v) = self.mesa_read("GetSerialNumber's reply", &[mesa::SERIAL_REPLY]) else {
            return self.mesa_end("no serial number");
        };
        if self.mesa_sbio(0x17, &v[9..25], None, false).is_none() {
            return self.mesa_end("SBIO 0x17 was not answered status 0");
        }

        // 3. prepareSession → performKeyExchange(1) (0xfffffe0009abec30): the UID session's share both ways
        let Some(r) = self.mesa_sbio(0x15, &1u32.to_le_bytes(), Some(40), false) else {
            return self.mesa_end("SBIO 0x15 did not give a 40-byte share");
        };
        if mesa::send_plain(mesa::T_SHARE, &r.data).is_err() {
            return self.mesa_end("the share's frame was not sent");
        }
        let Some(v) = self.mesa_read("the key exchange's reply", &[mesa::SHARE_REPLY]) else {
            return self.mesa_end("no key exchange reply");
        };
        if self.mesa_sbio(0x16, &v[9..49], None, false).is_none() {
            return self.mesa_end("SBIO 0x16 was not answered status 0");
        }

        // 4. initializeSequenceCounter (0xfffffe0009ac1aa0)
        let Some(r) = self.mesa_sbio(0x42, &[], Some(64), false) else {
            return self.mesa_end("SBIO 0x42 did not give a 64-byte challenge");
        };
        if mesa::send_plain(mesa::T_SEQUENCE, &r.data).is_err() {
            return self.mesa_end("the challenge's frame was not sent");
        }
        let Some(v) = self.mesa_read("the sequence counter's reply", &[mesa::SEQUENCE_REPLY]) else {
            return self.mesa_end("no sequence counter reply");
        };
        if self.mesa_sbio(0x18, &v[9..73], None, false).is_none() {
            return self.mesa_end("SBIO 0x18 was not answered status 0");
        }

        // 5. loadPatch (0xfffffe0009ac1090): the patch from the SEP, then to the sensor raw after SetupPatchEnable
        let Some(r) = self.sbio_transact(0x5f, &2u16.to_le_bytes(), false, 0x50_0000) else {
            return self.mesa_end("SBIO 0x5F's patch did not come");
        };
        if r.status != 0 || r.data.is_empty() {
            dev_err!(self.dev, "[sep2] mesa: SBIO 0x5F: status {:#x}, {:#x} bytes\n", r.status, r.data.len());
            return self.mesa_end("SBIO 0x5F did not give a patch");
        }
        let h = sks::sha256(&r.data);
        dev_info!(self.dev, "[sep2] mesa: the patch: {:#x} bytes, sha256 {}\n", r.data.len(), Hex(&h[..8]));
        if mesa::command(mesa::T_SETUP_PATCH).is_err() {
            return self.mesa_end("SetupPatchEnable was not sent");
        }
        let Some(s) = self.mesa_event("SetupPatchEnable's status", 1, 5, mesa::STEP_MS, false) else {
            return self.mesa_end("no event after SetupPatchEnable");
        };
        if s.state() != mesa::STATE_IDLE {
            return self.mesa_end("SetupPatchEnable's event is not in state 0");
        }
        if let Err(e) = mesa::patch(&r.data) {
            dev_err!(self.dev, "[sep2] mesa: the patch's transfer: {:?}\n", e);
            return self.mesa_end("the patch was not sent");
        }
        // after the patch macOS reads nothing until the interrupt: the polls begin 20 ms on, every 20 ms
        let Some(s) = self.mesa_event("the patch's status", 20, 20, 2000, false) else {
            return self.mesa_end("no event after the patch");
        };
        if s.result() != mesa::RESULT_DONE {
            return self.mesa_end("the patch's event is not 0x29, patch load done");
        }
        dev_info!(self.dev, "[sep2] mesa: the patch is loaded, version {:#x}\n", s.patch_version());

        // 6. applySensorParams(0) (0xfffffe0009abc2b4)
        for (op, data) in [(0x5d, &[0u8; 4][..]), (0x5c, &[0u8; 8][..])] {
            let Some(r) = self.sbio_query(op, data, false) else {
                return self.mesa_end("a parameter op was not answered");
            };
            if r.status != 0 {
                dev_err!(self.dev, "[sep2] mesa: {}: status {:#x} (0x12d: a restart)\n", proto::sbio_name(op), r.status);
                return self.mesa_end("a parameter op was refused");
            }
            if !self.mesa_param(op, &r.data) {
                return self.mesa_end("the sensor did not take a parameter frame");
            }
        }
        let Some(r) = self.sbio_query(0x6a, &[], false) else {
            return self.mesa_end("SBIO 0x6A was not answered");
        };
        if r.status != 0 {
            dev_err!(self.dev, "[sep2] mesa: SBIO 0x6A: status {:#x} (0x12d: a restart)\n", r.status);
            return self.mesa_end("SBIO 0x6A was refused");
        }
        if r.data.is_empty() {
            dev_info!(self.dev, "[sep2] mesa: SBIO 0x6A gave nothing: skipped, as macOS skips it\n");
        } else if !self.mesa_param(0x6a, &r.data) {
            return self.mesa_end("the sensor did not take 0x6A's frame");
        }

        // 7. GetStatus, then getSensorModuleSerialNumberRaw (0xfffffe0009abfdd8)
        match mesa::status() {
            Ok(s) => self.mesa_log("GetStatus", &s),
            Err(_) => return self.mesa_end("GetStatus failed"),
        }
        let Some(r) = self.mesa_sbio(0x31, &[], Some(64), false) else {
            return self.mesa_end("SBIO 0x31 did not give a 64-byte challenge");
        };
        if mesa::send_encrypted(&r.data, 0x49, mesa::ENC_XFER, &[]).is_err() {
            return self.mesa_end("the module serial number's frame was not sent");
        }
        let Some(v) = self.mesa_read("the module serial number's reply", &[0x4b, 0x4f]) else {
            return self.mesa_end("no module serial number reply");
        };
        let n = v.len();
        if mesa::crc16(&v[..n - 2]) != u16::from_le_bytes([v[n - 2], v[n - 1]]) {
            return self.mesa_end("the module serial number's reply fails its CRC (macOS checks it)");
        }
        let Some(r) = self.mesa_sbio(0x32, &v[9..n - 2], Some(18), false) else {
            return self.mesa_end("SBIO 0x32 did not give 18 bytes");
        };
        drop(r);

        // 8. COMPLETE_INIT and the match policy
        if self.mesa_sbio(0x01, &[], None, true).is_none() || self.mesa_sbio(0x1f, &[], None, true).is_none() {
            return self.mesa_end("SBIO 0x01 or 0x1F was not answered status 0");
        }
        if self.stage == 11 {
            let how = self.run_capture();
            dev_info!(self.dev, "[sep2] capture: {}\n", how);
            self.state.lock().sbio.capture = Some(how);
        }
        if self.stage >= 12 {
            let how = self.run_enrol();
            dev_info!(self.dev, "[sep2] enrol: {}\n", how);
            self.state.lock().sbio.enrol = Some(how);
        }
        let off = mesa::power(false).is_ok();
        dev_info!(self.dev, "[sep2] mesa: the bring-up done as on macOS; the power {}\n", if off { "off" } else { "not switched" });
        self.state.lock().sbio.mesa = Some("the bring-up done: the session, the patch, the parameters, the module serial");
        true
    }

    // --- the bring-up ---

    /// Sleeps up to `ms`, in slices, unless the driver is going away; false if it is.
    fn nap(&self, ms: u32) -> bool {
        let mut left = ms;
        while left > 0 {
            if self.closing.load(Relaxed) {
                return false;
            }
            let d = left.min(POLL_MS);
            time::delay::fsleep(time::Delta::from_millis(i64::from(d)));
            left -= d;
        }
        !self.closing.load(Relaxed)
    }

    /// Waits for the first discovery message, then for a quiet spell. Not for any message: what iBoot left in
    /// the SEP-to-AP FIFO arrives as the mailbox starts, before the registration is even sent.
    fn wait_discovery(&self) -> bool {
        let mut waited = 0;
        while self.state.lock().n_apps == 0 {
            if waited >= FIRST_RESPONSE_MS || !self.nap(POLL_MS) {
                return false;
            }
            waited += POLL_MS;
        }
        let mut last = self.rx_total();
        let mut quiet = 0;
        while quiet < QUIET_MS && waited < SETTLE_MAX_MS {
            if !self.nap(POLL_MS) {
                return false;
            }
            waited += POLL_MS;
            let now = self.rx_total();
            if now == last {
                quiet += POLL_MS;
            } else {
                last = now;
                quiet = 0;
            }
        }
        true
    }

    fn log_discovery(&self) {
        let st = self.state.lock();
        dev_info!(self.dev, "[sep2] discovery: {} endpoints in {} messages\n", st.n_apps, st.rx_total);
        for a in &st.apps[..st.n_apps] {
            dev_info!(
                self.dev,
                "[sep2]   endpoint {:#04x} '{}' sizes {:#010x}\n",
                a.ep,
                FourCc(a.name.unwrap_or(0)),
                a.sizes.unwrap_or(0)
            );
        }
    }

    /// The apps to enable must be where 14.8.3 had them, with its sizes; otherwise nothing is sent.
    fn check_apps(&self, apps: &[App]) -> bool {
        let st = self.state.lock();
        let mut ok = true;
        for &app in apps {
            match st.find(app.ep()) {
                Some(a) if a.name == Some(app.fourcc()) && a.sizes == Some(app.sizes_word()) => {}
                found => {
                    ok = false;
                    dev_err!(
                        self.dev,
                        "[sep2] {} is not as on macOS 14.8.3 (endpoint {:#04x}, sizes {:#010x}): found {}\n",
                        app.name(),
                        app.ep(),
                        app.sizes_word(),
                        match found {
                            Some(_) => "a different name or sizes there",
                            None => "nothing at that endpoint",
                        }
                    );
                }
            }
        }
        ok
    }

    /// A step's data: its constant, or its app's buffer address >> 12 (none if the stage gave it no buffer).
    fn step_data(&self, s: &Step) -> Option<u32> {
        let iova = match s.data {
            Data::Const(v) => return Some(v),
            Data::InAddr => self.ool_iova[app_index(s.app)?].0,
            Data::OutAddr => self.ool_iova[app_index(s.app)?].1,
        };
        if iova == 0 {
            return None;
        }
        u32::try_from(iova >> proto::UNIT_SHIFT).ok()
    }

    /// Sends one step and waits for its ack; false ends the sequence.
    fn run_step(&self, i: usize, total: usize, s: &Step) -> bool {
        let Some(data) = self.step_data(s) else {
            dev_err!(self.dev, "[sep2] step {}/{}: no buffer for {}\n", i, total, s.app.name());
            return false;
        };
        let param = s.app.ep();
        let req = proto::Word::new(proto::EP_CONTROL, s.tag, s.op, param, data);
        let msg = req.msg();
        if !self.state.lock().ctl.arm(req) {
            return false;
        }
        dev_info!(
            self.dev,
            "[sep2] step {}/{} (sep-1.log:{}): {} {}\n",
            i,
            total,
            s.line,
            s.app.name(),
            op_name(s.op)
        );
        if self.send(msg, op_name(s.op)).is_err() {
            self.state.lock().ctl.disarm();
            dev_err!(self.dev, "[sep2] step {}/{}: the send failed; sequence stopped\n", i, total);
            return false;
        }

        let mut remaining = time::msecs_to_jiffies(proto::CONTROL_TIMEOUT_MS);
        let mut st = self.state.lock();
        let reply = loop {
            if let Some(r) = st.ctl.take() {
                break Some(r);
            }
            if remaining == 0 || self.closing.load(Relaxed) {
                break None;
            }
            remaining = match self.wq.wait_interruptible_timeout(&mut st, remaining) {
                CondVarTimeoutResult::Woken { jiffies } => jiffies,
                CondVarTimeoutResult::Signal { jiffies } => jiffies,
                CondVarTimeoutResult::Timeout => 0,
            };
        };
        st.ctl.disarm();
        drop(st);

        let Some(r) = reply else {
            dev_err!(
                self.dev,
                "[sep2] step {}/{}: no ack to tag {:#04x} op {:#04x} param {:#04x} within {} ms; sequence stopped, nothing more is sent\n",
                i,
                total,
                req.tag,
                req.op,
                req.param,
                proto::CONTROL_TIMEOUT_MS
            );
            return false;
        };
        if r.op != proto::CONTROL_ACK || r.param != 0 {
            dev_err!(self.dev, "[sep2] step {}/{}: the reply is op {:#04x} param {:#04x}, not an ack; sequence stopped\n", i, total, r.op, r.param);
            return false;
        }
        if req.op == proto::OP_SECMODE {
            dev_info!(self.dev, "[sep2] step {}/{}: security mode {} (macOS 14.8.3 got 3)\n", i, total, r.data);
            return true;
        }
        if r.data != req.data {
            dev_err!(
                self.dev,
                "[sep2] step {}/{}: the ack echoes {:#010x}, not {:#010x}; sequence stopped\n",
                i,
                total,
                r.data,
                req.data
            );
            return false;
        }
        true
    }

    fn run_steps(&self, name: &str, steps: &[Step]) -> bool {
        for (i, s) in steps.iter().enumerate() {
            if !self.run_step(i + 1, steps.len(), s) {
                dev_err!(self.dev, "[sep2] {}: stopped at step {}\n", name, i + 1);
                return false;
            }
        }
        dev_info!(self.dev, "[sep2] {}: all {} steps acked\n", name, steps.len());
        true
    }

    fn bringup(&self) {
        dev_info!(self.dev, "[sep2] stage {}: waiting for the discovery\n", self.stage);
        if !self.wait_discovery() {
            dev_err!(
                self.dev,
                "[sep2] no answer to the registration within {} ms (m1n1 older than r73, or an earlier registration this boot): nothing more is sent\n",
                FIRST_RESPONSE_MS
            );
            self.summary();
            return;
        }
        self.log_discovery();

        let ok = 'seq: {
            if self.stage == 0 {
                dev_info!(self.dev, "[sep2] stage 0: step 1 only, nothing more is sent\n");
                break 'seq true;
            }
            let apps: &[App] = if self.stage >= 2 { &ALL_APPS } else { &ALL_APPS[..2] };
            if !self.check_apps(apps) {
                dev_err!(self.dev, "[sep2] the discovery differs from macOS's: nothing more is sent\n");
                break 'seq false;
            }
            if !self.run_steps("hdcp, xarm, security mode", &proto::STAGE1) {
                break 'seq false;
            }
            if self.stage >= 3 && !self.run_hdcp() {
                break 'seq false;
            }
            if self.stage >= 2 && !self.run_steps("stac", &proto::STAGE2) {
                break 'seq false;
            }
            if self.stage >= 3 {
                if !self.run_stac_power() {
                    break 'seq false;
                }
                self.open_xart();
            }
            if self.stage >= 6 && !self.run_sks() {
                break 'seq false;
            }
            if self.stage >= 8 && !self.run_sbio() {
                break 'seq false;
            }
            if self.stage >= 9 && !self.run_mesa() {
                break 'seq false;
            }
            if (10..=11).contains(&self.stage) && !self.run_credential() {
                break 'seq false;
            }
            true
        };
        dev_info!(
            self.dev,
            "[sep2] stage {} {}; watching for {} ms\n",
            self.stage,
            if ok { "done" } else { "STOPPED" },
            WATCH_MS
        );
        if self.nap(WATCH_MS) {
            self.summary();
        }
    }

    fn summary(&self) {
        let rx = self.rx_total();
        dev_info!(
            self.dev,
            "[sep2] summary: {} sent, {} received ({} dropped), {} xART requests held, {} xART writes refused\n",
            self.tx_count.load(Relaxed),
            rx,
            self.rx.lost(),
            self.xarm_held.load(Relaxed),
            self.xarm_refused.load(Relaxed)
        );
        if self.stage >= 3 {
            if let Some(s) = self.xart.lock().as_ref() {
                dev_info!(
                    self.dev,
                    "[sep2] xART: the .gl copy in memory, never written, holds {} records, revision {:#x}\n",
                    s.used(),
                    s.rev()
                );
            }
            let st = self.state.lock();
            dev_info!(
                self.dev,
                "[sep2] xART: {} replies sent; the service {}; {} requests held now ({} past the list)\n",
                self.xarm_served.load(Relaxed),
                match (st.serving, st.stopped) {
                    (false, _) => "never opened",
                    (true, None) => "open",
                    (true, Some(_)) => "opened, then stopped",
                },
                st.n_held,
                st.held_lost
            );
            if let Some(why) = st.stopped {
                dev_info!(self.dev, "[sep2] xART: it stopped at {}\n", why);
            }
        }
        if self.stage >= 6 {
            let k = self.state.lock().sks;
            dev_info!(
                self.dev,
                "[sep2] keystore: {} requests sent, {} replies (digests: {} good, {} bad), {} stray replies, {} of the SEP's own messages (not answered); the start-up: {}\n",
                k.sent,
                k.replies,
                k.digest_good,
                k.digest_bad,
                k.stray,
                k.sep_msgs,
                k.outcome.unwrap_or("never began")
            );
            if self.stage >= 7 {
                dev_info!(self.dev, "[sep2] identity: {}\n", k.identity.unwrap_or("never began"));
            }
            if self.stage >= 8 {
                let b = self.state.lock().sbio;
                dev_info!(
                    self.dev,
                    "[sep2] sbio: {} transactions, {} replies ({} refused), {} of the SEP's own messages (not answered); {}; scrd: {}\n",
                    b.sent,
                    b.replies,
                    b.refused,
                    b.sep_msgs,
                    b.outcome.unwrap_or("never began"),
                    b.scrd.unwrap_or("never sent")
                );
            }
            if self.stage >= 9 {
                let m = self.state.lock().sbio.mesa;
                dev_info!(self.dev, "[sep2] mesa: {}\n", m.unwrap_or("never began"));
            }
            if self.stage >= 10 {
                let c = self.state.lock().sbio.cred;
                dev_info!(self.dev, "[sep2] credential: {}\n", c.unwrap_or("never began"));
            }
            if self.stage == 11 {
                let c = self.state.lock().sbio.capture;
                dev_info!(self.dev, "[sep2] capture: {}\n", c.unwrap_or("never began"));
            }
            if self.stage >= 12 {
                let c = self.state.lock().sbio.enrol;
                dev_info!(self.dev, "[sep2] enrol: {}\n", c.unwrap_or("never began"));
            }
        }
        let b = self.bufs.lock();
        for app in BUF_APPS {
            let Some(i) = app_index(app) else { continue };
            if let Some(p) = &b.ool[i] {
                let (ni, fi) = nonzero(&p.inbound, 0, app.ool_size());
                let (no, fo) = nonzero(&p.outbound, 0, app.ool_size());
                dev_info!(
                    self.dev,
                    "[sep2] {} buffers: in {} nonzero bytes (first at {:#x}), out {} (first at {:#x})\n",
                    app.name(),
                    ni,
                    fi.unwrap_or(0),
                    no,
                    fo.unwrap_or(0)
                );
            }
        }
        if let Some(s) = &b.shmem {
            let (n, first) = nonzero(s, shmem::CINP_OFFSET, shmem::CINP_LEN);
            if let Some(first) = first {
                dev_warn!(self.dev, "[sep2] CINP, the SEP's panic channel, holds {} nonzero bytes from {:#x}:\n", n, first);
                // SAFETY: as in nonzero().
                let s = unsafe { &s.as_ref()[shmem::CINP_OFFSET..shmem::CINP_OFFSET + shmem::CINP_LEN] };
                let start = first & !0x7f;
                // The first 32 bytes from the first nonzero one in hex: a length word or a state
                // byte would not show as text.
                let mut h = [0u8; 96];
                for (i, &c) in s[first..].iter().take(32).enumerate() {
                    let x = b"0123456789abcdef";
                    h[3 * i] = x[(c >> 4) as usize];
                    h[3 * i + 1] = x[(c & 15) as usize];
                    h[3 * i + 2] = b' ';
                }
                let n_hex = 3 * core::cmp::min(32, s.len() - first);
                dev_warn!(self.dev, "[sep2] CINP +{:#x}: {}\n", first, core::str::from_utf8(&h[..n_hex]).unwrap_or("?"));
                for line in s[start..].chunks(128).take(8) {
                    let mut t = [b'.'; 128];
                    for (d, &c) in t.iter_mut().zip(line) {
                        if c.is_ascii_graphic() || c == b' ' {
                            *d = c;
                        }
                    }
                    let t = core::str::from_utf8(&t[..line.len()]).unwrap_or("?");
                    dev_warn!(self.dev, "[sep2] CINP | {}\n", t);
                }
            } else {
                dev_info!(self.dev, "[sep2] CINP, the SEP's panic channel, is still zero\n");
            }
        }
    }

    fn remove(&self) {
        self.closing.store(true, Relaxed);
        self.wq.notify_all();
        *self.mbox.lock() = None;
        let mut b = self.bufs.lock();
        if self.shm_given.load(Relaxed) {
            // The SEP holds these addresses until the next reset: never free them.
            if let Some(s) = b.shmem.take() {
                core::mem::forget(s);
            }
            for slot in b.ool.iter_mut() {
                if let Some(p) = slot.take() {
                    core::mem::forget(p);
                }
            }
            dev_warn!(self.dev, "[sep2] unbound after the registration: its buffers stay allocated; do not remove the SEP DART (sep-on.ko) before a reboot\n");
        }
    }
}

impl MailCallback for SepData {
    type Data = Arc<SepData>;

    // Called in the mailbox's hard IRQ: the message goes into the ring and the work logs it.
    fn recv_message(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, msg: Message) {
        if data.closing.load(Relaxed) {
            return;
        }
        let _ = data.rx.put(msg);
        let this: Arc<SepData> = data.into();
        let _ = workqueue::system_percpu().enqueue::<Arc<SepData>, 0>(this);
    }
}

impl WorkItem<0> for SepData {
    type Pointer = Arc<SepData>;

    fn run(this: Arc<SepData>) {
        if this.closing.load(Relaxed) {
            return;
        }
        this.drain();
    }
}

impl WorkItem<1> for SepData {
    type Pointer = Arc<SepData>;

    fn run(this: Arc<SepData>) {
        if this.closing.load(Relaxed) {
            return;
        }
        this.bringup();
    }
}

struct SepDriver(Arc<SepData>);

kernel::of_device_table!(OF_TABLE, (), [(of::DeviceId::new(c"apple,t6031-sep"), ())]);

impl platform::Driver for SepDriver {
    type IdInfo = ();
    type Data<'bound> = SepDriver;

    const OF_ID_TABLE: Option<of::IdTable<()>> = Some(&OF_TABLE);

    fn probe<'bound>(
        pdev: &'bound platform::Device<device::Core<'_>>,
        _info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        let dev: &device::Device<device::Core<'_>> = pdev.as_ref();
        if !machine_is_t6034() {
            dev_err!(dev, "[sep2] not a t6034: this lab driver is for the M3 Max's warm SEP only\n");
            return Err(ENODEV);
        }
        if REGISTERED.load(Relaxed) {
            dev_err!(dev, "[sep2] the registration was already sent this boot (one-shot per reset): reboot to attach again; not probing\n");
            return Err(EBUSY);
        }
        let stage = dev
            .fwnode()
            .ok_or(ENODEV)?
            .property_read::<u32>(STAGE_PROP)
            .optional()
            .unwrap_or(0);
        if stage > STAGE_MAX {
            dev_err!(dev, "[sep2] stage {} is not 0-{}\n", stage, STAGE_MAX);
            return Err(EINVAL);
        }

        // The SEP DART's window starts above 4 GiB (0x100_0000_4000).
        // SAFETY: probe has not allocated DMA memory for this device yet.
        unsafe { pdev.dma_set_mask_and_coherent(dma::DmaMask::new::<42>())? };

        let data = SepData::new(pdev, stage)?;
        if stage >= 7 {
            sks::IDENTITY_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 8 {
            proto::SBIO_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 9 {
            proto::SBIO9_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 10 {
            proto::CRED_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 12 {
            proto::ENROL_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        *data.mbox.lock() = Some(Mailbox::new_byname(dev, c"mbox", data.clone())?);

        // The last fallible step: from here, teardown goes through remove(), which keeps the buffers.
        match data.register() {
            Ok(()) => {
                let _ = workqueue::system_long().enqueue::<Arc<SepData>, 1>(data.clone());
            }
            Err(e) => dev_err!(dev, "[sep2] registration not sent ({:?}); nothing more is sent\n", e),
        }
        Ok(SepDriver(data))
    }
}

impl Drop for SepDriver {
    fn drop(&mut self) {
        self.0.remove();
    }
}

module_platform_driver! {
    type: SepDriver,
    name: "apple_sep",
    description: "Apple SEP: Touch ID steps 1-10b lab driver (warm attach, enables, xART service, key store, SBIO, the sensor, a capture, the enrolment's credential)",
    license: "GPL",
}
