// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) The Asahi Linux Contributors
#![recursion_limit = "2048"]

//! Apple SEP: Touch ID on the M3 Max (t6034): the daily flow, and the lab's stages behind a node property.
//!
//! Asahi's sep.rs (the platform driver, the mailbox, the DMA buffers) with macOS's warm path in place of its cold
//! boot: iBoot boots the sepOS before m1n1, and macOS's AppleSEPManager then only registers its shared memory and
//! enables the apps, which each stage below follows in macOS's order (docs/hardware/TOUCHID.md, SEP-PROTOCOLS.md).
//!
//! iBoot boots the sepOS (`/chosen/sepfw-load-at-boot`). The DT has the SEP's DART, mailbox and this node
//! (`apple,t6031-sep`), which m1n1 fills through the `sep` alias (the boot manifests, the sepfw region, the OS UUID,
//! protected-data-access, cpx-encryption-mode); without `apple,sep2-stage` the driver runs the daily flow, stage 17's.
//! The lab module `sep-on.ko` enables the nodes, or adds them on a DT without them, with the stage:
//! - 0: register the shared memory (endpoint 0xFE), log the discovery, send nothing more (step 1);
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
//! - 12: as 9, then the sensor's factory calibration loaded (0x5B with the FDR record `apple-sep-calibration.bin`,
//!   0x63) and the bring-up run again, as macOS runs both (mesa_calibrate); then between the bring-up and the
//!   power-off an enrolment cancelled before its save (Touch ID step 10c, run_enrol): the system context (0x2d −1), the components' states (0x6b), the user's context (0x2d, 0x2b),
//!   the credential of stage 10 kept open, BEGIN_ENROL 0x03, then per image a capture as stage 11's, relayed as
//!   27.2 relays it (0x23, 0x06, 0x65 in two packets, 0x07, 0x08 for an image the SEP takes, 0x22) until 0x08's
//!   done flag or the first refusal; then the cancel 0x05 and the credential closed. No save (0x6c, 0x37, 0x70);
//!   an xART write request is held as at stage 7 and ends the step. The images are zeroed after their relay.
//! - 13: as 12, with the SEP's xART writes carried to the `.gl` on the disk as macOS 27.2 carries them (Touch ID
//!   step 10d): the file's extents on the iBoot System Container from the firmware loader (`apple-sep-xart.ext`),
//!   the partition opened read and write and the whole file on it checked against the copy before attaching
//!   (sep/disk.rs, disk.c); a root or locker write, or a delete that finds its record, then goes to a fresh slot in the
//!   copy and on the disk, the old slot cleared after, each synced and read back from the disk, before status 0
//!   (write_through). A complete enrolment is saved instead of cancelled (enrol_save): per component its sealed
//!   catacomb (0x6c) handed to the host at debugfs `apple-sep/save.bin`, confirmed (0x37) once the host answers at
//!   `save.ack` that it holds it on its disk; then the lockout record (0x70) to the host. With sep-on.ko's
//!   disk_test=1, only the disk path runs, on a loop copy of the partition, and the SEP is never messaged.
//! - 14: as 13 after a reboot, with a match in place of the enrolment (Touch ID step 10e, run_match): the records
//!   stage 13 saved, from the firmware loader (`apple-sep-saved.bin`), loaded back verbatim (0x6d per catacomb not
//!   active by 0x6b, the master's first, then 0x71), then an unlock match (per touch 0x23, 0x06 with the match's flags and user, 0x65,
//!   0x07, 0x09 for a usable image, 0x22) until 0x09 names a user or 5 touches; then the save-pending components and
//!   the lockout record saved as at stage 13.
//! - 15: as 13 up to the calibration and the bring-up run again, the sensor off, then Touch ID's operations open to
//!   userspace at `/dev/apple-sep-bio` (bio.rs, include/uapi/linux/apple-sep-bio.h): the info, a sealed record
//!   loaded back (0x6d, 0x71) and a user's identities (0x6e), one at a time; the SEP's xART writes go to the `.gl`
//!   as at stage 13.
//! - 16: as 15, with an enrolment and a match open there too (bio.rs): each powers the sensor and runs the bring-up
//!   again (mesa_pass), opens the credential, and takes one touch per CAPTURE as stage 13's and 14's take them; its
//!   END powers the sensor off and leaves the save to userspace, a record per SAVE_NEXT, each confirmed (0x37) only
//!   once userspace says it holds it.
//! - 17 (absent): Touch ID's daily flow: as 16 with no identity at probe. The bring-up runs the key store's start-up but not
//!   stage 7's identity, and SBIO's 0x33 skips the user; the identity (its UUID, secret and uid, and the kept bag or
//!   none) comes later from userspace through UNLOCK on `/dev/apple-sep-bio`, which runs stage 7's sequence then and
//!   hands a new bag back; ENROL and MATCH wait for it. The `.gl` from the disk through disk.c's `xart` parameter or
//!   the loader's copy as before.
//!
//! Every message sent and received is logged with the prefix `[sep2]`. What may be sent is fixed by
//! proto::allowed, checked in `SepData::send`, the only way to the mailbox: the registration once per boot,
//! and the control endpoint's out-of-line size and address ops for those three apps and the security-mode
//! request; at stage 3 also hdcp's two ops, stac's power-on and the xART replies. Below stage 3 no message answers
//! the SEP: the xART service's requests (endpoint 0x13) are logged and held, as macOS holds them until its
//! gigalocker is open. A root or locker write is refused at every stage (logged, never serviced, never answered),
//! and so is a locker delete that finds its record; one that finds none is answered from stage 5. At stage 6 also
//! sks's size and address ops and the key store's three start-up requests, at stage 7 the identity's eight commands, at stage 8 scrd's and sbio's enables, stage 8's
//! SBIO queries and scrd's INITIALIZE, at stage 12 the enrolment's ops, at stage 13 the save's; with the FIDO2
//! authenticator on (`apple_sep.fido`, stage 17), the key store's kc_wrap, kc_unwrap and perform_operation. The module has no APFS
//! code; its block-device access is disk.c's (stage 13), its sensor access sensor.c's; it sends no boot, reset or
//! power message.

/// The lab's logging (`apple_sep.verbose=1`): every message, SBIO transaction, key store reply and the sensor's
/// status. Without it the driver logs that /dev/apple-sep-bio is ready, one line per operation and the errors. No
/// identity bytes (its UUID, its secret, the key store's images) at either level.
static VERBOSE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(crate) fn verbose() -> bool {
    VERBOSE.load(core::sync::atomic::Ordering::Relaxed)
}

/// dev_info! under `verbose`.
macro_rules! vinfo {
    ($($t:tt)*) => {
        if $crate::verbose() {
            kernel::dev_info!($($t)*)
        }
    };
}

mod apfs;
mod bio;
mod ctl;
mod disk;
mod fido;
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
        Mutex,
        SetOnce, //
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

/// The node property sep-on.ko sets from its `stage` parameter for the lab's stages.
const STAGE_PROP: &CStr = c"apple,sep2-stage";
const STAGE_MAX: u32 = 17;
/// Without the property: Touch ID's daily flow, stage 17's.
const STAGE_DAILY: u32 = 17;
/// The daily flow: how long the bring-up waits for the sensor's driver to bind (the SPI controller's and the
/// sensor's modules load from udev beside this one).
const SENSOR_WAIT_MS: u32 = 30_000;

/// Stage 3 without disk.c's `xart` parameter: the `.gl` copy, by the firmware loader (the run sets its path to a tmpfs
/// directory).
const XART_FW: &CStr = c"apple-sep-xart.gl";
/// Stage 7: the identity, 52 bytes: its UUID (16), its secret (32) and the uid whose session it unlocks (u32 LE).
const IDENTITY_FW: &CStr = c"apple-sep-identity.bin";
/// Stage 7: the wrapped identity bag a previous run's copy_keybag returned (absent: the run creates one).
const IDENTITY_BAG_FW: &CStr = c"apple-sep-identity.kb";
/// Stage 13 without the `xart` parameter: the `.gl` file's extents on the iBoot System Container (sep/disk.rs).
const XART_EXT_FW: &CStr = c"apple-sep-xart.ext";
/// Stage 14: the records stage 13's save handed to the host (Saved).
const SAVED_FW: &CStr = c"apple-sep-saved.bin";
/// Stage 12 on: the sensor's factory calibration (calibration_inputs).
const CALIBRATION_FW: &CStr = c"apple-sep-calibration.bin";
/// Stage 14: the touches one match may take.
const MATCH_IMAGES: u32 = 5;
/// Stage 13 with sep-on.ko's disk_test=1: the disk path run on the partition the extents name (a loop copy of the
/// iBoot System Container), the SEP never messaged, then not attaching.
const DISK_TEST_PROP: &CStr = c"apple,sep2-disk-test";
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
/// Stage 12: the images an enrolment may take (the SEP says when it is complete, and macOS has no count; 10c and
/// 10d completed at the 7th touch), the window for each (macOS's enrolment times out; 60 s here), and the pause after each for the finger
/// to lift and come back (each image its own touch: the touch's first, as after a finger detect).
const ENROL_IMAGES: u32 = 20;
const ENROL_CAPTURE_MS: u32 = 60_000;
const ENROL_LIFT_MS: u32 = 1_500;
/// Stage 13: how long the host has to keep a saved record and acknowledge it, and how often that is looked for.
const SAVE_ACK_MS: u32 = 30_000;
const SAVE_POLL_MS: u32 = 100;
/// 0x08's done flag without an error: the enrolment is complete.
const ENROL_COMPLETE: &str = "the enrolment complete (0x08's done flag)";
/// capture_image's answer to a cancel (bio.rs).
const CAPTURE_CANCELLED: &str = "the capture cancelled";
/// capture_image's answer when no finger came.
const CAPTURE_NO_IMAGE: &str = "no image within the window";
/// save_components' answer when every record went to the host.
const ENROL_SAVED: &str = "the enrolment saved: the catacombs kept and confirmed, the lockout record kept";
/// xART requests held before the service opens (macOS: one, op 0x0e) or after it stops.
const HELD_MAX: usize = 16;
/// The users whose lock state is kept (one session a boot; the master and the lab's 501 beside it).
const LOCKS_MAX: usize = 8;

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
    /// Stage 17: each user's last lock state from the SEP's request 1 (proto::SEP_REQ_LOCK_STATE), {uid, state}.
    locks: [(u32, u16); LOCKS_MAX],
    n_locks: usize,
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
    /// The image used for the enrolment, the progress (0-255), the assessment's feedback.
    Next(bool, u8, u32),
    Done(&'static str),
}

/// An SBIO transaction's answer: its status (an error packet's, or u32::MAX for one with status 0) and its data.
struct SbioReply {
    status: u32,
    /// kvmalloc'ed: a saved record runs to 0x500000 bytes.
    data: KVVec<u8>,
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

/// Stage 13's input: the `.gl` file's extents, those stage 3 read the file through (the `xart` parameter's or found), else
/// apple-sep-xart.ext checked against the copy's size; the partition opened read and write (disk.c checks it is the
/// 500 MB "iBootSystemContainer"), and the whole file on it compared with the copy, so the extents are right and
/// nothing changed it since the copy was taken. Anything else and the driver does not attach: nothing is sent.
fn disk_inputs(dev: &device::Device<device::Core<'_>>, store: &xart::Store, param: Option<disk::Extents>) -> Result<disk::Extents> {
    let ext = match param {
        Some(ext) => ext,
        None => {
            let fw = Firmware::request(XART_EXT_FW, dev).inspect_err(|e| {
                dev_err!(dev, "[sep2] stage 13: no apple-sep-xart.ext from the firmware loader ({:?}): not attaching\n", e);
            })?;
            disk::Extents::new(&fw, store.size()).map_err(|why| {
                dev_err!(dev, "[sep2] stage 13: the extents file: {}: not attaching\n", why);
                EINVAL
            })?
        }
    };
    disk::open(&ext, true).inspect_err(|e| {
        dev_err!(dev, "[sep2] stage 13: the partition {:?} did not open read and write ({:?}): not attaching\n", ext.dev(), e);
    })?;
    match disk::holds(&ext, 0, store.bytes(0, store.size())) {
        Ok(true) => {}
        Ok(false) => {
            disk::close();
            dev_err!(dev, "[sep2] stage 13: the .gl on the disk differs from the copy: not attaching\n");
            return Err(EINVAL);
        }
        Err(why) => {
            disk::close();
            dev_err!(dev, "[sep2] stage 13: the .gl's read through the extents: {}: not attaching\n", why);
            return Err(EINVAL);
        }
    }
    vinfo!(dev, "[sep2] stage 13: the .gl's {} extents on {:?} hold the copy; xART writes go to the disk\n", ext.count(), ext.dev());
    Ok(ext)
}

/// biometrickitd's save list (BiometricSupport `-[BiometricKitXPCServer getCatacombSaveListForComponents:list:]`
/// 0x238a2ac0c, with no list given): the components 0x6b shows save-pending (bit 2, active or not) but the master,
/// in 0x6b's order, then the master (−1) when any one is, the master included.
fn save_order(comps: &[(i32, u32)]) -> Result<KVec<i32>> {
    let pending = |st: u32| st & proto::COMPONENT_SAVE_PENDING != 0;
    let mut v = KVec::new();
    for &(w, _) in comps.iter().filter(|c| c.0 != proto::USER_SYSTEM && pending(c.1)) {
        v.push(w, GFP_KERNEL)?;
    }
    if comps.iter().any(|c| pending(c.1)) {
        v.push(proto::USER_SYSTEM, GFP_KERNEL)?;
    }
    Ok(v)
}

/// Stage 14's input: the records stage 13 handed to the host, as sep-step10e.sh packs them from its files: "SAVD",
/// u32 the count, then per record {u32 the kind (1 a catacomb, 2 the lockout record), i32 the component, u32 the
/// length, the bytes}: the catacombs in their save order (the master's first), the lockout record last. Each
/// catacomb's header must name its component at 8, as 0x6c's check did.
struct Saved {
    recs: KVec<(u32, i32, KVVec<u8>)>,
}

fn saved_inputs(dev: &device::Device<device::Core<'_>>) -> Result<Saved> {
    let fw = Firmware::request(SAVED_FW, dev).inspect_err(|e| {
        dev_err!(dev, "[sep2] stage 14: no apple-sep-saved.bin from the firmware loader ({:?}): not attaching\n", e);
    })?;
    let d = fw.data();
    let le = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    let bad = |why: &str| {
        dev_err!(dev, "[sep2] stage 14: the saved records: {}: not attaching\n", why);
        EINVAL
    };
    if d.len() < 8 || &d[..4] != b"SAVD" {
        return Err(bad("not a saved-records file"));
    }
    let (n, mut at) = (le(4) as usize, 8);
    let mut recs = KVec::new();
    for i in 0..n {
        if at + 12 > d.len() {
            return Err(bad("cut short"));
        }
        let (kind, who, len) = (le(at), le(at + 4) as i32, le(at + 8) as usize);
        at += 12;
        if len == 0 || len > proto::SAVE_MAX || at + len > d.len() {
            return Err(bad("a record's length"));
        }
        let rec = &d[at..at + len];
        at += len;
        let last = i + 1 == n;
        match kind {
            1 if !last && len > proto::CATACOMB_HEADER
                && i32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]) == who => {}
            2 if last => {}
            _ => return Err(bad("a record's kind, place or header")),
        }
        let mut v = KVVec::new();
        v.extend_from_slice(rec, GFP_KERNEL)?;
        let (what, shown) = if kind == 1 { ("the catacomb of component", who) } else { ("the lockout record", 0) };
        let h = sks::sha256(rec);
        vinfo!(dev, "[sep2] stage 14: {} {}, {:#x} bytes, sha256 {}\n", what, shown, len, Hex(&h[..8]));
        recs.push((kind, who, v), GFP_KERNEL)?;
    }
    if at != d.len() || n < 2 {
        return Err(bad("trailing bytes, or fewer than a catacomb and the lockout record"));
    }
    Ok(Saved { recs })
}

/// Stage 12's input: the sensor's factory calibration, the Hardware volume's FDR record `FSCl-<serial>` as macOS's
/// FactoryData cache holds it (docs/hardware/TOUCHID.md, the iBoot System Container): a DER sequence {"comb",
/// {"fdrd", the IMG4: FSCl's IM4P and its manifest}, {"secb", ...}}, 0xfff8 bytes here. Stage 3's read of it beside the
/// found `.gl` when it has one, else the lab's copy by the firmware loader. Only its shape is checked: the SEP checks
/// its signature and the sensor's serial number in it (setCalibrationData's 0x12e and 0x12f). It is per-device factory
/// data, never logged, nor its file's name (the serial).
fn calibration_inputs(
    dev: &device::Device<device::Core<'_>>,
    found: Option<core::result::Result<KVVec<u8>, &'static str>>,
) -> Result<KVVec<u8>> {
    let (v, from) = match found {
        Some(Ok(v)) => (v, "the disk's"),
        Some(Err(why)) => {
            dev_err!(dev, "[sep2] stage 12: the calibration beside the found .gl: {}: not attaching\n", why);
            return Err(EINVAL);
        }
        None => {
            let fw = Firmware::request(CALIBRATION_FW, dev).inspect_err(|e| {
                dev_err!(dev, "[sep2] stage 12: no apple-sep-calibration.bin from the firmware loader ({:?}): not attaching\n", e);
            })?;
            let mut v = KVVec::new();
            v.extend_from_slice(fw.data(), GFP_KERNEL)?;
            (v, "the loader's")
        }
    };
    let d = &v[..];
    // 30 82 hi lo: a sequence whose two-byte length covers the file, then 16 04 "comb"
    if d.len() < 10
        || d.len() > proto::CALIBRATION_MAX
        || d[..2] != [0x30, 0x82]
        || usize::from(u16::from_be_bytes([d[2], d[3]])) + 4 != d.len()
        || &d[4..10] != b"\x16\x04comb"
    {
        dev_err!(dev, "[sep2] stage 12: {} calibration ({:#x} bytes) is not one FDR \"comb\" record: not attaching\n", from, d.len());
        return Err(EINVAL);
    }
    vinfo!(dev, "[sep2] stage 12: the sensor's calibration, {}, an FDR record of {:#x} bytes (not logged)\n", from, v.len());
    Ok(v)
}

/// Stage 13: gl_rec_write carried to the disk as macOS carries it: the plan; the disk checked to hold the copy's
/// bytes where the write goes (the new slot whole, the old slot's first 0x1000 bytes); the copy written in memory;
/// then the new slot whole and the old slot's cleared start written through, each synced and read back. A refusal
/// of gl_rec_write's changes nothing and is returned for its status. Err: the disk did not hold the copy, or a write or
/// its read-back failed; the copy may then be ahead of the disk, and the caller stops the service.
fn write_through(store: &mut xart::Store, ext: &disk::Extents, k: &xart::Key, data: &[u8]) -> core::result::Result<xart::Write, &'static str> {
    let (slot, old) = match store.plan(k, data) {
        Ok(p) => p,
        Err((status, why)) => return Ok(xart::Write::Refused { status, why }),
    };
    let at = slot * xart::SLOT;
    if !disk::holds(ext, at, store.bytes(at, xart::SLOT))? {
        return Err("the disk's new slot differs from the copy's: nothing written");
    }
    if let Some(o) = old {
        if !disk::holds(ext, o * xart::SLOT, store.bytes(o * xart::SLOT, xart::DELETE))? {
            return Err("the disk's old slot differs from the copy's: nothing written");
        }
    }
    let w = store.write(k, data);
    match w {
        xart::Write::Done { slot: s, old: o, .. } if s == slot && o == old => {}
        _ => return Err("the copy's write went elsewhere than its plan: nothing written to the disk"),
    }
    disk::write(ext, at, store.bytes(at, xart::SLOT))?;
    if let Some(o) = old {
        disk::write(ext, o * xart::SLOT, store.bytes(o * xart::SLOT, xart::DELETE))?;
    }
    Ok(w)
}

/// Stage 13: gl_rec_delete carried to the disk: the slot's first 0x1000 bytes checked, cleared in the copy, written
/// through, synced and read back.
fn delete_through(store: &mut xart::Store, ext: &disk::Extents, slot: usize) -> core::result::Result<(), &'static str> {
    let at = slot * xart::SLOT;
    if !disk::holds(ext, at, store.bytes(at, xart::DELETE))? {
        return Err("the disk's slot differs from the copy's: nothing deleted");
    }
    store.delete(slot);
    disk::write(ext, at, store.bytes(at, xart::DELETE))
}

/// Stage 13's disk test, on a loop copy of the iBoot System Container: each root record written again with its own
/// bytes (a fresh slot, the old one cleared, the revision one up, as the SEP's own writes would go), then the whole
/// file read back from the disk, compared with the copy and parsed as gl_open would. The SEP is never messaged.
fn disk_test(dev: &device::Device<device::Core<'_>>, store: &mut xart::Store, ext: &disk::Extents) -> core::result::Result<(), &'static str> {
    let rev0 = store.rev();
    for (ty, name) in [(xart::TYPE_ROOT_USER, "user"), (xart::TYPE_ROOT_SEP, "SEP")] {
        let k = xart::root_key(ty);
        let mut data = KVec::new();
        match store.find(&k, xart::ROOT_MAX) {
            xart::Lookup::Found(rec) => data.extend_from_slice(rec.data, GFP_KERNEL).map_err(|_| "no memory")?,
            _ => return Err("a root record missing or bad in the copy"),
        }
        match write_through(store, ext, &k, &data)? {
            xart::Write::Done { slot, old, rev, .. } => vinfo!(
                dev,
                "[sep2] disk test: the {} root record, {:#x} bytes, written to slot {} (from {:?}), revision {:#x}, synced and read back\n",
                name, data.len(), slot, old, rev
            ),
            xart::Write::Refused { status, why } => {
                dev_err!(dev, "[sep2] disk test: the {} root record refused, status {}: {}\n", name, status, why);
                return Err("a refusal");
            }
        }
    }
    let size = store.size();
    if !disk::holds(ext, 0, store.bytes(0, size))? {
        return Err("the disk's .gl differs from the copy after the writes");
    }
    let mut back = KVVec::from_elem(0u8, size, GFP_KERNEL).map_err(|_| "no memory")?;
    disk::read(ext, 0, &mut back)?;
    let again = xart::Store::from_bytes(&back)?;
    if again.rev() != rev0 + 2 || again.used() != store.used() {
        return Err("the disk's .gl parses with another revision or count");
    }
    vinfo!(dev, "[sep2] disk test: the disk's .gl equals the copy and parses as gl_open wants it: {} used, revision {:#x} (from {:#x})\n", again.used(), again.rev(), rev0);
    Ok(())
}

/// Stage 3's `.gl` without the lab's copy: the partition the `xart` parameter names opened read-only (disk.c checks
/// it is the 500 MB "iBootSystemContainer"), its APFS container checked against the parameter's UUID, the file read
/// through the extents and closed again.
fn xart_from_disk(dev: &device::Device<device::Core<'_>>, ext: &disk::Extents, uuid: &[u8; 16]) -> Result<xart::Store> {
    disk::open(ext, false).inspect_err(|e| {
        dev_err!(dev, "[sep2] stage 3: the partition {:?} did not open ({:?}): not attaching\n", ext.dev(), e);
    })?;
    let r = (|| -> core::result::Result<xart::Store, &'static str> {
        disk::container_is(uuid)?;
        let mut gl = KVVec::from_elem(0u8, ext.size(), GFP_KERNEL).map_err(|_| "no memory")?;
        disk::read(ext, 0, &mut gl)?;
        xart::Store::from_bytes(&gl)
    })();
    disk::close();
    r.map_err(|why| {
        dev_err!(dev, "[sep2] stage 3: the .gl on {:?} through the xart parameter's {} extents: {}: not attaching\n", ext.dev(), ext.count(), why);
        EINVAL
    })
}

/// Stage 3's `.gl` and stage 12's calibration from the iBoot System Container, found by the driver (disk.c among the
/// block devices, apfs.rs in its APFS container): the `.gl` read through the extents found, the partition read-only.
/// None when no disk holds the partition (the loader's copies then); Err when one does and the files are not read.
#[allow(clippy::type_complexity)]
fn xart_from_scan(
    dev: &device::Device<device::Core<'_>>,
) -> Result<Option<(xart::Store, disk::Extents, core::result::Result<KVVec<u8>, &'static str>)>> {
    let (major, minor) = match disk::find() {
        Ok(d) => d,
        Err(e) => {
            vinfo!(dev, "[sep2] stage 3: no iBoot System Container found ({:?}): the loader's copies\n", e);
            return Ok(None);
        }
    };
    let found = disk::scan(major, minor).map_err(|why| {
        dev_err!(dev, "[sep2] stage 3: the iBoot System Container on ({}, {}): {}: not attaching\n", major, minor, why);
        EINVAL
    })?;
    let r = (|| -> core::result::Result<xart::Store, &'static str> {
        let mut gl = KVVec::from_elem(0u8, found.gl.size(), GFP_KERNEL).map_err(|_| "no memory")?;
        disk::read(&found.gl, 0, &mut gl)?;
        xart::Store::from_bytes(&gl)
    })();
    disk::close();
    let store = r.map_err(|why| {
        dev_err!(dev, "[sep2] stage 3: the .gl found on ({}, {}) through {} extents: {}: not attaching\n", major, minor, found.gl.count(), why);
        EINVAL
    })?;
    vinfo!(dev, "[sep2] stage 3: the .gl found on ({}, {}): {} extents, read-only\n", major, minor, found.gl.count());
    Ok(Some((store, found.gl, found.calibration)))
}

/// Stage 3's inputs: the `.gl` (from the disk through the `xart` parameter's extents, else found on the disk by the
/// driver, else the lab's copy by the firmware loader), both root records checked as gl_rec_read checks them, the OS
/// UUID and protected-data-access; with the found `.gl`, the calibration read beside it for stage 12. The extents
/// read through stage 13 then takes. Anything missing or wrong and the driver does not attach: nothing is sent.
#[allow(clippy::type_complexity)]
fn xart_inputs(
    dev: &device::Device<device::Core<'_>>,
) -> Result<(Option<xart::Store>, Option<[u8; 16]>, u8, Option<disk::Extents>, Option<core::result::Result<KVVec<u8>, &'static str>>)> {
    let param = disk::Extents::from_param().map_err(|why| {
        dev_err!(dev, "[sep2] stage 3: {}: not attaching\n", why);
        EINVAL
    })?;
    let (store, ext, from, calibration) = match param {
        Some((ext, uuid)) => (xart_from_disk(dev, &ext, &uuid)?, Some(ext), "the disk's", None),
        None => match xart_from_scan(dev)? {
            Some((store, ext, cal)) => (store, Some(ext), "the disk's, found", Some(cal)),
            None => {
                let fw = Firmware::request(XART_FW, dev).inspect_err(|e| {
                    dev_err!(dev, "[sep2] stage 3: no apple-sep-xart.gl from the firmware loader ({:?}): not attaching\n", e);
                })?;
                let store = xart::Store::new(&fw).map_err(|why| {
                    dev_err!(dev, "[sep2] stage 3: the .gl copy holds {}: not attaching\n", why);
                    EINVAL
                })?;
                (store, None, "the loader's", None)
            }
        },
    };
    vinfo!(
        dev,
        "[sep2] stage 3: the .gl, {} copy, {:#x} bytes, {} slots, {} used, revision {:#x}, each record as gl_fixup_rev_init wants it; in memory only\n",
        from,
        store.size(),
        store.slots(),
        store.used(),
        store.rev()
    );
    for (ty, name) in [(xart::TYPE_ROOT_SEP, "SEP"), (xart::TYPE_ROOT_USER, "user")] {
        match store.find(&xart::root_key(ty), xart::ROOT_MAX) {
            xart::Lookup::Found(r) => vinfo!(
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
    vinfo!(
        dev,
        "[sep2] stage 3: {}, protected-data-access {}\n",
        if os_uuid.is_some() { "an OS UUID (not logged)" } else { "no OS UUID (op 0x13 gets status 2)" },
        pda
    );
    Ok((Some(store), os_uuid, pda, ext, calibration))
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
            vinfo!(dev, "[sep2] stage 6: cpx-encryption-mode {} (the node's, from the ADT's /defaults)\n", m);
            m
        }
        None => {
            vinfo!(dev, "[sep2] stage 6: no apple,cpx-encryption-mode: the 27.0.1 ADT's {}\n", CPX_DEFAULT);
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
    vinfo!(dev, "[sep2] stage 7: the identity file, for uid {} (session handle -{}); its UUID and secret are not logged\n", id.uid, id.uid);
    if let Ok(fw) = Firmware::request_nowarn(IDENTITY_BAG_FW, dev) {
        let b = fw.data();
        if b.is_empty() || b.len() > sks::BUF_LEN / 2 {
            dev_err!(dev, "[sep2] stage 7: the kept bag is {} bytes: not attaching\n", b.len());
            return Err(EINVAL);
        }
        let mut v = KVec::with_capacity(b.len(), GFP_KERNEL)?;
        v.extend_from_slice(b, GFP_KERNEL)?;
        vinfo!(dev, "[sep2] stage 7: a kept bag, {:#x} bytes, sha256 {}\n", v.len(), Hex(&sks::sha256(&v)[..8]));
        id.bag = Some(v);
    } else {
        vinfo!(dev, "[sep2] stage 7: no kept bag: the run creates the identity\n");
    }
    Ok(id)
}

/// debugfs `apple-sep/identity.kb`.
type BagFile = Pin<KBox<debugfs::File<Mutex<KVec<u8>>>>>;
/// Stage 13: debugfs `apple-sep/save.bin`, the record the host is to keep, and `apple-sep/save.ack`, its answer.
type SaveFile = Pin<KBox<debugfs::File<Mutex<KVVec<u8>>>>>;
type AckFile = Pin<KBox<debugfs::File<Atomic<u64>>>>;

#[pin_data]
struct SepData {
    dev: ARef<device::Device>,
    stage: u32,
    shmem_iova: u64,
    ool_iova: [(u64, u64); 6],
    /// Stage 6: set_env's cpx-encryption-mode.
    cpx_mode: u32,
    /// Stage 7: the identity, from the identity file at probe; at stage 17 from UNLOCK (bio.rs), once a boot.
    identity: SetOnce<Identity>,
    /// Stage 14: the records stage 13 saved.
    saved: Option<Saved>,
    /// Stage 12: the sensor's factory calibration.
    calibration: Option<KVVec<u8>>,
    /// Stage 13: the `.gl` file's extents, the partition open read and write (sep/disk.rs).
    disk: Option<disk::Extents>,
    /// Stage 7: debugfs `apple-sep/identity.kb`, the wrapped bag copy_keybag returned, for the run to keep.
    bag_file: Option<BagFile>,
    /// Stage 13: debugfs `apple-sep/save.bin` and `save.ack` (hand_to_host).
    save_file: Option<SaveFile>,
    ack_file: Option<AckFile>,
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
    /// Stage 13: the xART writes and deletes carried to the disk.
    xarm_written: Atomic<u32>,
    xarm_served: Atomic<u32>,
    shm_given: Atomic<bool>,
    closing: Atomic<bool>,

    /// Stage 15: operations may run (bio.rs): set once the bring-up is done.
    bio_ready: Atomic<bool>,
    /// Stage 15: the bring-up stopped short of the service; no operation runs this boot.
    bio_stopped: Atomic<bool>,
    /// Stage 15: one operation at a time, and what it left open (an enrolment or a match, a save).
    #[pin]
    bio_op: Mutex<bio::OpState>,
    /// One key store request at a time (sks_call), whoever sends it: the bring-up, bio.rs, the authenticator.
    #[pin]
    sks_serial: Mutex<()>,
    /// `apple_sep.fido`: the authenticator's CTAP2 state (fido.rs), held by the request in flight; its CTAPHID state,
    /// held by the host's writer for one packet; its HID device (fido.c), sent to under `fido_tx`; and the handle its
    /// keys use: the kept bag's from the bring-up, else the user's session's from the identity's unlock.
    #[pin]
    fido: Mutex<Option<fido::Auth>>,
    #[pin]
    fido_hid: Mutex<Option<fido::Hid>>,
    #[pin]
    fido_tx: Mutex<()>,
    fido_dev: core::sync::atomic::AtomicPtr<core::ffi::c_void>,
    fido_handle: core::sync::atomic::AtomicI32,
    /// The request fido_work runs, the channel it is on (0: none in flight) and whether the host cancelled it.
    #[pin]
    fido_req: Mutex<Option<(u32, KVec<u8>)>>,
    fido_busy: core::sync::atomic::AtomicU32,
    fido_cancel: core::sync::atomic::AtomicBool,
    /// Stage 15: a cancel asked for the operation in flight (bio.rs), checked by the capture's wait.
    bio_cancel: Atomic<bool>,
    /// A match the driver ran itself (bio::verify) left the SEP a newer lockout record than userspace keeps: SAVE_NEXT
    /// opens its save. Read and written under `bio_op`.
    lockout_dirty: Atomic<bool>,
    /// The last capture window ended with no finger and the sensor still armed: the next capture goes on from it.
    capture_armed: Atomic<bool>,
    /// Stage 15: `/dev/apple-sep-bio`, from probe until remove().
    #[pin]
    service: Mutex<Option<Pin<KBox<bio::Service>>>>,

    #[pin]
    rx_work: Work<SepData, 0>,
    #[pin]
    bringup_work: Work<SepData, 1>,
    #[pin]
    fido_work: Work<SepData, 2>,
}

impl_has_work! {
    impl HasWork<Self, 0> for SepData { self.rx_work }
    impl HasWork<Self, 1> for SepData { self.bringup_work }
    impl HasWork<Self, 2> for SepData { self.fido_work }
}

// SAFETY: every field is synchronised (the mutexes, the atomics, the inbox's atomic slots) or
// immutable after construction; the DMA buffers are written only in probe, before the SEP knows them.
unsafe impl Send for SepData {}
// SAFETY: see above.
unsafe impl Sync for SepData {}

impl SepData {
    fn new(pdev: &platform::Device<device::Core<'_>>, stage: u32) -> Result<Arc<SepData>> {
        let dev: &device::Device<device::Core<'_>> = pdev.as_ref();

        let (store, os_uuid, pda, param_ext, found_cal) = if stage >= 3 { xart_inputs(dev)? } else { (None, None, 1, None, None) };
        let cpx_mode = if stage >= 6 { sks_inputs(dev)? } else { 0 };
        let identity = if (7..=16).contains(&stage) { Some(identity_inputs(dev)?) } else { None };
        let disk = if stage >= 13 { Some(disk_inputs(dev, store.as_ref().ok_or(EINVAL)?, param_ext)?) } else { None };
        let saved = if stage == 14 { Some(saved_inputs(dev)?) } else { None };
        if let (Some(ext), true) = (&disk, dev.fwnode().is_some_and(|n| n.property_present(DISK_TEST_PROP))) {
            let mut store = store;
            let r = disk_test(dev, store.as_mut().ok_or(EINVAL)?, ext);
            disk::close();
            match r {
                Ok(()) => vinfo!(dev, "[sep2] disk test: passed; the SEP was never messaged: not attaching\n"),
                Err(why) => dev_err!(dev, "[sep2] disk test: FAILED: {}; the SEP was never messaged: not attaching\n", why),
            }
            return Err(ENODEV);
        }
        let calibration = if stage >= 12 { Some(calibration_inputs(dev, found_cal)?) } else { None };
        let (debugfs, bag_file) = if stage >= 7 {
            let d = debugfs::Dir::new(c"apple-sep");
            let f = KBox::pin_init(d.read_binary_file(c"identity.kb", new_mutex!(KVec::new())), GFP_KERNEL)?;
            (Some(d), Some(f))
        } else {
            (None, None)
        };
        let (save_file, ack_file) = match (&debugfs, stage >= 13) {
            (Some(d), true) => (
                Some(KBox::pin_init(d.read_binary_file(c"save.bin", new_mutex!(KVVec::new())), GFP_KERNEL)?),
                Some(KBox::pin_init(d.write_only_file(c"save.ack", Atomic::new(0u64)), GFP_KERNEL)?),
            ),
            _ => (None, None),
        };

        let built = shmem::build(pdev)?;
        let shmem_iova = built.buf.dma_address();
        if !iova_ok(shmem_iova, shmem::SHMEM_SIZE) {
            dev_err!(dev, "[sep2] refusing to attach: the shared memory's address {:#x} is outside the SEP DART's window\n", shmem_iova);
            return Err(EINVAL);
        }
        vinfo!(
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
            vinfo!(dev, "[sep2] {} buffers: in {:#x}, out {:#x}, {:#x} bytes each\n", app.name(), a, b, size);
            ool_iova[i] = (a, b);
            ool[i] = Some(OolPair { inbound, outbound });
        }

        let identity_once = SetOnce::new();
        if let Some(id) = identity {
            identity_once.populate(id);
        }
        Arc::pin_init(
            try_pin_init!(SepData {
                dev: ARef::<device::Device>::from(pdev.as_ref()),
                stage,
                shmem_iova,
                ool_iova,
                cpx_mode,
                identity: identity_once,
                disk,
                saved,
                calibration,
                bag_file,
                save_file,
                ack_file,
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
                    locks: [(0, 0); LOCKS_MAX],
                    n_locks: 0,
                }),
                wq <- new_condvar!("SepData::wq"),
                rx: inbox::Inbox::new(),
                rx_dropped_logged: Atomic::new(0),
                tx_count: Atomic::new(0),
                xarm_held: Atomic::new(0),
                xarm_refused: Atomic::new(0),
                xarm_written: Atomic::new(0),
                xarm_served: Atomic::new(0),
                shm_given: Atomic::new(false),
                closing: Atomic::new(false),
                bio_ready: Atomic::new(false),
                bio_stopped: Atomic::new(false),
                bio_op <- new_mutex!(bio::OpState::default()),
                sks_serial <- new_mutex!(()),
                fido <- new_mutex!(None),
                fido_hid <- new_mutex!(None),
                fido_tx <- new_mutex!(()),
                fido_dev: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                fido_handle: core::sync::atomic::AtomicI32::new(0),
                fido_req <- new_mutex!(None),
                fido_busy: core::sync::atomic::AtomicU32::new(0),
                fido_cancel: core::sync::atomic::AtomicBool::new(false),
                bio_cancel: Atomic::new(false),
                lockout_dirty: Atomic::new(false),
                capture_armed: Atomic::new(false),
                service <- new_mutex!(None),
                rx_work <- new_work!("SepData::rx_work"),
                bringup_work <- new_work!("SepData::bringup_work"),
                fido_work <- new_work!("SepData::fido_work"),
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
        vinfo!(
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
                    vinfo!(
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
                let word = u16::from(f.op) | (u16::from(f.param) << 8);
                if f.tag == proto::SEP_REQ_LOCK_STATE {
                    let n = st.n_locks;
                    match st.locks[..n].iter().position(|l| l.0 == f.data) {
                        Some(i) => st.locks[i].1 = word,
                        None if n < LOCKS_MAX => {
                            st.locks[n] = (f.data, word);
                            st.n_locks += 1;
                        }
                        None => {}
                    }
                }
                rx!("sbio: the SEP's own message, request {}, length or state {:#x}, info {:#x} (not answered)",
                    f.tag, word, f.data);
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
        vinfo!(self.dev, "[sep2] hdcp: {} interfaces (14.8.3: 14)\n", f.data);
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
        vinfo!(self.dev, "[sep2] hdcp: all {} interfaces launched, each result 0, size 8\n", f.data);
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
            vinfo!(
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
        vinfo!(
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
                vinfo!(
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
                vinfo!(self.dev, "[sep2] xART: no {} locker for the key: status 0, nothing\n", who);
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
            Ok((crc_ok, Some(slot))) => vinfo!(
                self.dev,
                "[sep2] xART: op {:#04x}, {} of the {}'s: {:#x} bytes, CRC-16 {:#06x} {}, its key's record in slot {}: held, never answered\n",
                r.op(), what, who, len, r.crc16(), if crc_ok { "good" } else { "BAD" }, slot
            ),
            Ok((crc_ok, None)) => vinfo!(
                self.dev,
                "[sep2] xART: op {:#04x}, {} of the {}'s: {:#x} bytes, CRC-16 {:#06x} {}, a new key: held, never answered\n",
                r.op(), what, who, len, r.crc16(), if crc_ok { "good" } else { "BAD" }
            ),
            Err(why) => vinfo!(self.dev, "[sep2] xART: op {:#04x}, {} of the {}'s, {:#x} bytes ({}): held, never answered\n", r.op(), what, who, len, why),
        }
        self.xarm_refused.store(self.xarm_refused.load(Relaxed) + 1, Relaxed);
        "an xART write: held, never answered (no write path to the disk)"
    }

    /// Stage 13: a root write (op 1) or a locker write (op 6) served as macOS 27.2 serves it (_handle_sep_driven_msg's
    /// cases 1 and 6, then gl_rec_write): the length checked as macOS checks it (a root record under 0x7ff0 bytes, a
    /// locker's UUID and 0-0x7ff0 bytes), the CRC-16 of the bytes against the request's (macOS panics on a mismatch:
    /// here the service stops), then write_through(), and status 0, or gl_rec_write's refusal's status with nothing
    /// written. The bytes and the UUID are never logged.
    fn write_served(&self, store: &mut xart::Store, msg: &Message, r: &xarm::Req) -> core::result::Result<Message, &'static str> {
        let ext = self.disk.as_ref().ok_or("no extents")?;
        let sep = Self::write_owner(r)?;
        let root = r.op() == xarm::OP_ROOT_WRITE;
        let len = usize::from(r.len());
        if (root && len > xart::ROOT_MAX) || (!root && (len < 16 || len - 16 > xart::SESSION_MAX)) {
            return Err("a write whose length macOS refuses");
        }
        let (crc_ok, uuid, data) = self.with_xarm_out(len, |o| {
            let mut u = [0u8; 16];
            let start = if root { 0 } else { 16 };
            if !root {
                u.copy_from_slice(&o[..16]);
            }
            let mut d = KVec::new();
            d.extend_from_slice(&o[start..], GFP_KERNEL).map(|_| (xart::crc16(o) == r.crc16(), u, d))
        })?
        .map_err(|_| "no memory")?;
        if !crc_ok {
            return Err("a write whose CRC-16 fails (macOS panics)");
        }
        let key = match (root, sep) {
            (true, false) => xart::root_key(xart::TYPE_ROOT_USER),
            (true, true) => xart::root_key(xart::TYPE_ROOT_SEP),
            (false, false) => xart::session_key(xart::TYPE_SESSION_USER, &uuid),
            (false, true) => xart::session_key(xart::TYPE_SESSION_SEP, &uuid),
        };
        let what = if root { "a root record" } else { "a locker" };
        let who = if sep { "SEP" } else { "user" };
        match write_through(store, ext, &key, &data)? {
            xart::Write::Done { slot, old, rev, crc32 } => {
                vinfo!(
                    self.dev,
                    "[sep2] xART: op {:#04x}, {} of the {}'s, {:#x} bytes, CRC-32 {:#010x}: slot {} (from {:?}), revision {:#x}, on the disk, synced and read back: status 0\n",
                    r.op(), what, who, data.len(), crc32, slot, old, rev
                );
                self.xarm_written.store(self.xarm_written.load(Relaxed) + 1, Relaxed);
                Ok(xarm::Req::of(msg).answer(xarm::STATUS_OK, 0, None))
            }
            xart::Write::Refused { status, why } => {
                vinfo!(self.dev, "[sep2] xART: op {:#04x}, {} of the {}'s, {:#x} bytes: refused as gl_rec_write refuses it ({}): status {}\n", r.op(), what, who, data.len(), why, status);
                Ok(xarm::Req::of(msg).answer(status, 0, None))
            }
        }
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
            None => vinfo!(
                self.dev,
                "[sep2] xART: op 0x07, no {} locker for the key: nothing deleted, status 0 (macOS logs '{}_XART_LOCKER ... not found')\n",
                who,
                who
            ),
            Some(slot) if self.stage >= 13 => {
                delete_through(store, self.disk.as_ref().ok_or("no extents")?, slot)?;
                vinfo!(self.dev, "[sep2] xART: op 0x07, the {} locker in slot {} deleted, on the disk, synced and read back: status 0\n", who, slot);
                self.xarm_written.store(self.xarm_written.load(Relaxed) + 1, Relaxed);
            }
            // The disk would keep a found record, behind the SEP after a reboot: not served before a disk write path.
            Some(slot) => {
                vinfo!(self.dev, "[sep2] xART: op 0x07 finds a {} locker in slot {}: not served\n", who, slot);
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
            xarm::OP_ROOT_WRITE | xarm::OP_SESSION_WRITE if self.stage >= 13 => {
                self.write_served(store.as_mut().ok_or("no .gl copy")?, msg, &r)
            }
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
                vinfo!(self.dev, "[sep2] xART: op {:#04x} ({}), '{}': logged, not answered, as macOS 27.2\n", r.op(),
                    match r.op() { 0x1d => "register_disable", 0x1e => "log_disable_begin", _ => "log_disable_acknowledge" }, shown);
                self.xarm_served.store(self.xarm_served.load(Relaxed) + 1, Relaxed);
                true
            }
            0x21 if r.len() != 0 => {
                let seen = self.with_xarm_out(5, |o| (o[0], u32::from_le_bytes([o[1], o[2], o[3], o[4]])));
                match seen {
                    Ok((v, x)) => vinfo!(self.dev, "[sep2] xART: op 0x21, the secure storage analytics: {:#x} bytes, version {}, value {:#x}: status 0\n", r.len(), v, x),
                    Err(why) => vinfo!(self.dev, "[sep2] xART: op 0x21, the secure storage analytics ({}): status 0\n", why),
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
                vinfo!(self.dev, "[sep2] xART: the service stops at {:#018x}: {}; it and every request after it are held\n", msg.msg0, why);
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
        vinfo!(self.dev, "[sep2] xART: the service opens on the .gl copy, {} requests held before\n", n);
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
        vinfo!(self.dev, "[sep2] keystore: the discovery named endpoint {:#04x} {} ms after the xART service opened\n", proto::EP_SKS, waited);
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
        let shown = r.body.len().min(if name.starts_with("copy_keybag") || name.starts_with("kc_") || name.starts_with("perform") { 8 } else { 32 });
        vinfo!(
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
            vinfo!(self.dev, "[sep2] keystore: {}'s reply carries an extended header of {:#x} bytes (device state; not decoded)\n", name, n);
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
        let _one = self.sks_serial.lock();
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
        vinfo!(
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
            vinfo!(self.dev, "[sep2] keystore: {}'s reply image, {:#x} bytes (not logged)\n", name, rlen);
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
        vinfo!(
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
        vinfo!(self.dev, "[sep2] keystore: set_env took cpx-encryption-mode {}: status 0, as on 14.8.3\n", self.cpx_mode);

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
        vinfo!(self.dev, "[sep2] keystore: null_d_key answered -1 ({:#x} bytes), as 14.8.3's, which logs it and goes on\n", w.len);
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
        self.stage < 7 || self.stage >= 17 || self.run_identity()
    }

    /// Stage 17's UNLOCK (bio.rs): the identity for this boot, then stage 7's sequence on it. Ok with the new wrapped
    /// bag when the identity came without one (the SEP made it), else None; Err with why, the identity kept for the
    /// boot either way (the SEP saw it: another one waits for a reboot).
    pub(crate) fn unlock(&self, id: Identity) -> core::result::Result<Option<KVec<u8>>, &'static str> {
        if self.stage < 17 {
            return Err("UNLOCK is stage 17's");
        }
        let fresh = id.bag.is_none();
        if !self.identity.populate(id) {
            return Err("an identity was given this boot already");
        }
        if !self.run_identity() {
            return Err(self.state.lock().sks.identity.unwrap_or("the identity's sequence stopped"));
        }
        if let Some(uid) = self.identity.as_ref().map(|id| id.uid) {
            self.fido_start(-(uid as i32));
        }
        if !fresh {
            return Ok(None);
        }
        let f = self.bag_file.as_ref().ok_or("no bag file")?;
        let mut v = KVec::new();
        v.extend_from_slice(&f.lock(), GFP_KERNEL).map_err(|_| "no memory for the new bag")?;
        Ok(Some(v))
    }

    /// REARM (bio.rs): the session's unlock sent again with the identity's secret, step 7.8's device_state_transition,
    /// as macOS's lock screen sends it once the user's password is typed. It clears the SEP's lockout of the user's
    /// matches: the user's lock state (the SEP's request 1) goes from 0x44 to 0x228 (PasscodeValidated), then 0x208
    /// (a lockout forced by SBIO 0x3d, 2026-11-10). The lockout record is saved by the save bio.rs opens after it.
    pub(crate) fn rearm(&self) -> core::result::Result<(), &'static str> {
        let id = self.identity.as_ref().ok_or("no identity this boot")?;
        let session = -(id.uid as i32);
        let before = self.lock_state(id.uid);
        let Some((_, img)) = self.identity_call("rearm: unlock", sks::CMD_DEVICE_STATE_TRANSITION, self.sks_seq(), sks::device_state_unlock(session, &id.secret)) else {
            return Err("device_state_transition was not answered status 0");
        };
        let parsed = sks::parse_device_state(self.reply_body(sks::CMD_DEVICE_STATE_TRANSITION, &img));
        vinfo!(self.dev, "[sep2] bio: uid {}'s session unlocked again: mask and time {:x?}; the user's lock state {:x?} before\n", id.uid, parsed, before);
        Ok(())
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
        vinfo!(self.dev, "[sep2] identity: handle {}'s state, {:#x} bytes (not logged)\n", handle, b.len());
        sks::lock_state(b)
    }

    /// A key store request of the authenticator's: its reply image on status 0, else None with the status logged.
    fn key_call(&self, what: &str, cmd: u8, body: Result<sks::Body>) -> Option<KVec<u8>> {
        let version = self.state.lock().sks.version;
        let body = body.ok()?;
        let (w, img) = self.sks_call(what, cmd, self.sks_seq(), version, &body)?;
        if w.status != 0 {
            dev_info!(self.dev, "[sep2] keys: {}: {} answered status {} ({:#x} bytes)\n", what, sks::cmd_name(cmd), w.status, w.len);
            return None;
        }
        Some(img)
    }

    /// A perform_operation on the authenticator's handle: the reply's DER result on status 0, else None (logged).
    fn key_op(&self, what: &str, der: Result<KVec<u8>>) -> Option<KVec<u8>> {
        let der = der.ok()?;
        let h = self.fido_handle.load(CR);
        let img = self.key_call(what, sks::CMD_PERFORM_OPERATION, sks::perform_operation(h, 2, &der))?;
        let Some(b) = sks::parse_blob(self.reply_body(sks::CMD_PERFORM_OPERATION, &img)) else {
            dev_err!(self.dev, "[sep2] keys: {}: the reply is not {{0, blob}}\n", what);
            return None;
        };
        let mut v = KVec::new();
        v.extend_from_slice(b, GFP_KERNEL).ok()?;
        Some(v)
    }

    /// The next key store sequence number, for requests after the identity's.
    fn sks_seq(&self) -> u8 {
        let mut st = self.state.lock();
        let s = st.sks.next_seq;
        st.sks.next_seq = s.wrapping_add(1);
        s
    }

    /// Stage 17 with the authenticator on: the kept bag (`apple-sep-identity.kb`, the identity's, which holds no
    /// secret) loaded with no secret at the bring-up's key store start-up, as the initramfs loads it before the root
    /// is open, and the authenticator started on it: its keys are in class dku, which the loaded bag opens, and they
    /// open on the user's session too. The handle stays loaded through the identity's unlock after (build 66).
    fn keys_early(&self) {
        if module_parameters::fido.value() == 0 {
            return;
        }
        let Ok(fw) = Firmware::request_nowarn(IDENTITY_BAG_FW, &self.dev) else {
            vinfo!(self.dev, "[sep2] keys: no apple-sep-identity.kb: the authenticator waits for the identity's unlock\n");
            return;
        };
        {
            // clear of the identity's own numbers (4 on)
            let mut st = self.state.lock();
            st.sks.next_seq = st.sks.next_seq.max(0x80);
        }
        let img = self.key_call("the kept bag", sks::CMD_LOAD_KEYBAG, sks::load_keybag(fw.data()));
        let Some(h) = img.as_ref().and_then(|i| sks::parse_handle(self.reply_body(sks::CMD_LOAD_KEYBAG, i))) else {
            dev_info!(self.dev, "[sep2] keys: the kept bag did not load\n");
            return;
        };
        vinfo!(self.dev, "[sep2] keys: the kept bag loaded with no secret, handle {}\n", h);
        self.fido_start(h);
    }

    /// The authenticator's HID device, its keys on `handle` (fido.rs), made once: the first handle stays.
    fn fido_start(&self, handle: i32) {
        if module_parameters::fido.value() == 0 || !self.fido_dev.load(CR).is_null() {
            return;
        }
        self.fido_handle.store(handle, CR);
        *self.fido.lock() = Some(fido::Auth::new());
        *self.fido_hid.lock() = Some(fido::Hid::new());
        let ctx = core::ptr::from_ref(self).cast_mut().cast::<core::ffi::c_void>();
        // SAFETY: the device lives until remove(), which destroys the HID device, and with it its callbacks, before
        // the SepData goes.
        let f = unsafe { fido::ffi::apple_sep_fido_create(self.dev.as_raw().cast(), ctx, fido_rx) };
        if f.is_null() || (f as isize) < 0 && (f as isize) >= -4095 {
            dev_err!(self.dev, "[sep2] fido: the HID device was not made ({})\n", f as isize);
            return;
        }
        self.fido_dev.store(f, CR);
        dev_info!(self.dev, "[sep2] fido: the FIDO2 authenticator is up\n");
    }

    /// A CTAPHID message to the host, framed into input reports; none once remove() has the device.
    fn fido_send(&self, cid: u32, cmd: u8, data: &[u8]) {
        let _tx = self.fido_tx.lock();
        let f = self.fido_dev.load(CR);
        if f.is_null() {
            return;
        }
        fido::Hid::frame(cid, cmd, data, |p: &[u8; 64]| {
            // SAFETY: `f` is live: remove() takes it under `fido_tx` before destroying it; `p` is 64 bytes.
            unsafe { fido::ffi::apple_sep_fido_send(f, p.as_ptr()) };
        });
    }

    /// One CTAPHID packet from the host's write: CTAPHID's replies at once; a whole CTAP2 request to fido_work, so
    /// the write never waits for the user and a CANCEL reaches the request waiting for the touch.
    fn fido_packet(this: &Arc<SepData>, pkt: &[u8; 64]) {
        let msg = {
            let mut guard = this.fido_hid.lock();
            let Some(hid) = Option::as_mut(&mut *guard) else { return };
            hid.packet(pkt)
        };
        match msg {
            fido::Msg::None => {}
            fido::Msg::Reply(cid, cmd, data) => this.fido_send(cid, cmd, &data),
            fido::Msg::Cancel(cid) => {
                if cid != 0 && this.fido_busy.load(CR) == cid {
                    this.fido_cancel.store(true, CR);
                }
            }
            fido::Msg::Cbor(cid, req) => {
                if this.fido_busy.compare_exchange(0, cid, CR, CR).is_err() {
                    this.fido_send(cid, fido::CMD_ERROR, &[fido::ERR_CHANNEL_BUSY]);
                    return;
                }
                this.fido_cancel.store(false, CR);
                *this.fido_req.lock() = Some((cid, req));
                // one request at a time (fido_busy), so the work is never pending here
                let _ = workqueue::system_long().enqueue::<Arc<SepData>, 2>(this.clone());
            }
        }
    }

    /// fido_work: the request in flight, its reply sent; the channel free before the reply goes, so the host's next
    /// request, which follows the reply, never finds it busy.
    fn fido_run(&self) {
        let Some((cid, req)) = self.fido_req.lock().take() else { return };
        let cmd = req.first().copied().unwrap_or(0);
        let reply = {
            let mut guard = self.fido.lock();
            match Option::as_mut(&mut *guard) {
                Some(auth) => auth.request(self, &req),
                None => KVec::new(),
            }
        };
        vinfo!(self.dev, "[sep2] fido: CTAP2 {:#04x}: status {:#04x}, {:#x} bytes\n", cmd, reply.first().copied().unwrap_or(0xff), reply.len());
        self.fido_busy.store(0, CR);
        if reply.is_empty() {
            self.fido_send(cid, fido::CMD_ERROR, &[fido::ERR_OTHER]);
        } else {
            self.fido_send(cid, fido::REPLY_CBOR, &reply);
        }
    }

    /// presence()'s tick, every 100 ms of the wait for the touch: KEEPALIVE (the user's touch needed) on the
    /// request's channel; false once the host cancelled it or the driver goes away.
    fn fido_keepalive(&self) -> bool {
        if self.fido_cancel.load(CR) || self.closing.load(Relaxed) {
            return false;
        }
        let cid = self.fido_busy.load(CR);
        if cid != 0 {
            self.fido_send(cid, fido::CMD_KEEPALIVE, &[fido::KEEPALIVE_UPNEEDED]);
        }
        true
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
                vinfo!(self.dev, "[sep2] identity: created, handle {}, fv_data {:#x} bytes\n", h, fv);
                let Some((_, img)) = self.identity_call("7.2 copy_keybag_uuid", sks::CMD_COPY_KEYBAG_UUID, next(), sks::copy_keybag_uuid(h)) else {
                    return self.identity_end("copy_keybag_uuid was not answered status 0");
                };
                let Some(u) = sks::parse_blob(self.reply_body(sks::CMD_COPY_KEYBAG_UUID, &img)) else {
                    return self.identity_end("copy_keybag_uuid's reply is not {0, blob}");
                };
                let same = if u == id.uuid.as_slice() { "equal to" } else { "not" };
                vinfo!(self.dev, "[sep2] identity: the bag's UUID, {} bytes, {} the identity file's\n", u.len(), same);
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
                vinfo!(self.dev, "[sep2] identity: the wrapped bag, {:#x} bytes, sha256 {}\n", v.len(), Hex(&sks::sha256(&v)[..8]));
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
        vinfo!(self.dev, "[sep2] identity: loaded the {} bag, handle {}\n", which, h2);
        self.state_probe("7.5a the session's state", session, next());
        self.state_probe("7.5b the bag's state", h2, next());
        let Some((_, img)) = self.identity_call("7.6 make_system_keybag", sks::CMD_MAKE_SYSTEM_KEYBAG, next(), sks::make_system_keybag(h2, session)) else {
            return self.identity_end("make_system_keybag v1 was not answered status 0");
        };
        let b = self.reply_body(sks::CMD_MAKE_SYSTEM_KEYBAG, &img);
        if !b.is_empty() && !sks::parse_version(b, 1) {
            return self.identity_end("make_system_keybag's reply is not version 1 alone");
        }
        vinfo!(self.dev, "[sep2] identity: designated for session {}\n", session);
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
        vinfo!(self.dev, "[sep2] identity: session {}'s unlock: mask {:#x} (the kext's {:#x}), time {:#x}, lock state {:?}\n", session, mask, e, time, sls);
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
            vinfo!(self.dev, "[sep2] sbio: {}: the request's {:#x} bytes in {} packets; the reply's sequence {}\n", name, data.len(), wseq, r.msg0 >> 48);
        }
        let f = proto::Word::of(&r);
        barrier::dma_mb(barrier::Read);
        // the header and the data, copied out under the buffers' lock alone
        let mut v = KVVec::new();
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
            } else if h[6] != h[1] && h[1] as usize > max_total {
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
            vinfo!(self.dev, "[sep2] sbio: {}: an error packet (msg0 {:#018x}), status {:#x}\n", name, r.msg0, status);
            let status = if status == 0 { u32::MAX } else { status };
            return Some(SbioReply { status, data: KVVec::new() });
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
            vinfo!(self.dev, "[sep2] sbio: {}: {:#x} bytes in {} packets\n", name, total, seq + 1);
        }
        {
            let mut st = self.state.lock();
            st.sbio.replies += 1;
            if status != 0 {
                st.sbio.refused += 1;
            }
        }
        if show {
            vinfo!(self.dev, "[sep2] sbio: {}: status {:#x}, flags {:#x}, {:#x} bytes: {}\n", name, status, flags, v.len(), Hex(&v[..v.len().min(0x100)]));
        } else {
            vinfo!(self.dev, "[sep2] sbio: {}: status {:#x}, flags {:#x}, {:#x} bytes\n", name, status, flags, v.len());
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
                vinfo!(self.dev, "[sep2] scrd: INITIALIZE's reply: request {}, {:#x} bytes, status {} (msg1 {:#x}): {}\n", request, len, status, r.msg1, Hex(&o[..n]));
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
        // stage 17: no identity at the bring-up, so no user's queries (0x38, the user's 0x33)
        let uid = self.identity.as_ref().map(|id| id.uid as i32);
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
            vinfo!(self.dev, "[sep2] sbio: {} identity records, {:#x} bytes over\n", r.data.len() / 40, r.data.len() % 40);
            for rec in r.data.chunks_exact(40) {
                let u = i32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                vinfo!(self.dev, "[sep2] sbio:   uid {}, then {}\n", u, Hex(&rec[20..]));
            }
        }
        // 0x38 v2: {uid, 1 (built-in), 16 zeros}
        if let Some(uid) = uid {
            let mut v2 = [0u8; 24];
            v2[..4].copy_from_slice(&uid.to_le_bytes());
            v2[4..8].copy_from_slice(&1u32.to_le_bytes());
            if self.sbio_query(0x38, &v2, true).is_none() {
                return self.sbio_end("0x38 was not answered in one packet");
            }
        }
        if self.sbio_query(0x39, &[], true).is_none() {
            return self.sbio_end("0x39 was not answered in one packet");
        }
        // 0x33: each catacomb's ID, compared with the .gl copy's lockers, never logged
        for who in [Some(-1i32), Some(501), uid].into_iter().flatten() {
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
                Some(ty) => vinfo!(self.dev, "[sep2] sbio: uid {}'s catacomb ID is a locker's in the .gl copy (type {})\n", who, ty),
                None => vinfo!(self.dev, "[sep2] sbio: uid {}'s catacomb ID matches no locker (all zero: {})\n", who, zero),
            }
        }
        for (op, uid) in uid.into_iter().flat_map(|u| [0x2b, 0x2e, 0x36].map(|op| (op, u))) {
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
        let taken = if scrd { "taken" } else { "not taken" };
        if let Some(uid) = uid {
            let seq = self.state.lock().sks.next_seq;
            let sls = self.state_probe("8 the session's state", -uid, seq);
            vinfo!(self.dev, "[sep2] sbio: done; scrd INITIALIZE {}; the session's lock state {:?}\n", taken, sls);
        } else {
            vinfo!(self.dev, "[sep2] sbio: done; scrd INITIALIZE {}; no session yet\n", taken);
        }
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
            vinfo!(self.dev, "[sep2] credential: {}: request {}, status {}, head v{} {:#x} bytes, output {:#x} bytes: {}\n", what, id, status, o[0], head, out.len(), Hex(&out[..out.len().min(0x80)]));
        } else {
            vinfo!(self.dev, "[sep2] credential: {}: request {}, status {}, head v{} {:#x} bytes, output {:#x} bytes\n", what, id, status, o[0], head, out.len());
        }
        let mut v = KVec::new();
        v.extend_from_slice(out, GFP_KERNEL).ok()?;
        Some((status, v))
    }

    /// The kept bag's secret verified into the context `acm` by the key store's verify_secret v1 (0x21). The forms in
    /// turn, until one is answered status 0 (a refused one changes nothing the run can see; an xART write it asked
    /// for would be held and end the step): the session's designated bag (-uid, as stage 7 designates it) with flags
    /// 0, then 0x100; then 27.2's identity_verify form, the wrapped bag loaded again, its handle, flags 0x100, then 0,
    /// unloaded after. The action mask, or why not.
    fn cred_verify(&self, bag: &[u8], secret: &[u8], acm: &[u8; proto::ACM_HANDLE_LEN], uid: u32, seq: &mut u8) -> core::result::Result<u64, &'static str> {
        let mut next = || {
            *seq = seq.wrapping_add(1);
            *seq
        };
        let session = -(uid as i32);
        for flags in [0, sks::VERIFY_FLAGS] {
            vinfo!(self.dev, "[sep2] credential: verify_secret on the session's bag {}, flags {:#x}\n", session, flags);
            if let Some((_, img)) = self.identity_call("10.4 verify_secret", sks::CMD_VERIFY_SECRET, next(), sks::verify_secret(session, secret, acm, flags)) {
                return sks::parse_verify(self.reply_body(sks::CMD_VERIFY_SECRET, &img)).ok_or("verify_secret's reply is not {1, mask}");
            }
        }
        let Some((_, img)) = self.identity_call("10.3 load", sks::CMD_LOAD_KEYBAG, next(), sks::load_keybag(bag)) else {
            return Err("load_keybag of the kept bag was not answered status 0");
        };
        let Some(h) = sks::parse_handle(self.reply_body(sks::CMD_LOAD_KEYBAG, &img)) else {
            return Err("load_keybag's reply is not {0, handle}");
        };
        vinfo!(self.dev, "[sep2] credential: the kept bag loaded, handle {}\n", h);
        let mut verified = None;
        for flags in [sks::VERIFY_FLAGS, 0] {
            vinfo!(self.dev, "[sep2] credential: verify_secret on the loaded bag {}, flags {:#x}\n", h, flags);
            if let Some((_, img)) = self.identity_call("10.4 verify_secret", sks::CMD_VERIFY_SECRET, next(), sks::verify_secret(h, secret, acm, flags)) {
                verified = Some(sks::parse_verify(self.reply_body(sks::CMD_VERIFY_SECRET, &img)));
                break;
            }
        }
        let unloaded = self.identity_call("10.5 unload", sks::CMD_UNLOAD_KEYBAG, next(), sks::unload_keybag(h)).is_some();
        let mask = match verified {
            None => return Err("verify_secret was not answered status 0 in any form"),
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
            vinfo!(self.dev, "[sep2] credential: a context for uid {}, tracking number {}, the SEP's log level {:#x}\n", uid, tracking, out[0x10]);
        }
        let mut seq = self.state.lock().sks.next_seq;
        let outcome: core::result::Result<(), &'static str> = 'chain: {
            match self.scrd_command("10.2 ExternalizeContext", proto::SCRD_CMD_EXTERNALIZE, &acm, true) {
                Some((0, _)) => {}
                Some(_) => break 'chain Err("the externalize was not answered status 0"),
                None => break 'chain Err("the externalize was not answered"),
            }
            match self.cred_verify(&bag, &id.secret, &acm, uid, &mut seq) {
                Ok(mask) => {
                    let e = sks::state_error(mask).unwrap_or(0);
                    vinfo!(self.dev, "[sep2] credential: verify_secret's action mask {:#x} (the kext's {:#x})\n", mask, e);
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
            vinfo!(self.dev, "[sep2] credential: TouchIdEnrollment {}, a requirement of {:#x} bytes\n", if satisfied { "satisfied" } else { "NOT satisfied" }, out.len() - 4);
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
        vinfo!(self.dev, "[sep2] credential: the context {}; the session's lock state {:?}\n", if deleted { "deleted" } else { "NOT deleted" }, sls);
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
        self.sensor_idle("stage 11's end");
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
    /// while a finger is placed: each change of state or of bytes 8, 10 and 11 logged with the time since the window
    /// began; in state 7 with 0x7200 bytes ready (else 0x4800, as handleStateMachine) the image read once. The image,
    /// the bytes ready and the time, or why not. Stops at an SPI error, a reset or recovery event, state 9, a cancel,
    /// or the window's end. A window that ends with no finger leaves the sensor armed, and the next goes on from it
    /// without a StartCapture: macOS keeps the capture armed until the operation ends (AppleMesaSEPDriver
    /// sensorStateHandler: Idle only when the command mode leaves enrol and match), and an Idle there never took effect
    /// (builds 50 to 53: the status stays armed, `11 02 21 80 04 80 80 80 80`). A cancel leaves it to the end's Idle.
    fn capture_image(&self, window: u32) -> core::result::Result<(KVec<u8>, u32, u32), &'static str> {
        let mut s = mesa::status().map_err(|_| "GetStatus failed before StartCapture")?;
        let armed = self.capture_armed.xchg(false, Relaxed);
        if armed && s.sane() && s.state() == mesa::STATE_ARMED {
            vinfo!(self.dev, "[sep2] capture: still armed from the last window ({}); a finger within {} s\n", Hex(&s.0), window / 1000);
        } else {
            self.mesa_log(if armed { "armed before, now" } else { "before StartCapture" }, &s);
            if s.sane() && s.state() != mesa::STATE_IDLE {
                s = self.sensor_idle("before StartCapture").ok_or("GetStatus failed while idling")?;
            }
            if !s.sane() || s.state() != mesa::STATE_IDLE {
                return Err("the sensor is not sane and idle before StartCapture");
            }
            mesa::command(mesa::T_START_CAPTURE).map_err(|_| "StartCapture was not sent")?;
            vinfo!(self.dev, "[sep2] capture: StartCapture sent; a finger on the sensor within {} s\n", window / 1000);
        }
        let mut last: Option<(u8, u8, u8, u8)> = None;
        let mut waited = 0u32;
        loop {
            let s = mesa::status().map_err(|_| "a status read failed during the capture")?;
            if last != Some((s.state(), s.0[8], s.0[10], s.0[11])) {
                last = Some((s.state(), s.0[8], s.0[10], s.0[11]));
                vinfo!(self.dev, "[sep2] capture: at {} ms: {} (state {} {}, [11] {:#04x}, ready {:#x})\n", waited, Hex(&s.0), s.state(), mesa::state_name(s.state()), s.0[11], s.count());
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
                self.capture_armed.store(s.state() == mesa::STATE_ARMED, Relaxed);
                return Err(CAPTURE_NO_IMAGE);
            }
            if self.bio_cancel.load(Relaxed) {
                return Err(CAPTURE_CANCELLED);
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
            vinfo!(self.dev, "[sep2] capture: slice {} header {}\n", i, Hex(&img[i * per..i * per + 7]));
        }
        vinfo!(
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
    fn enrol_sbio(&self, op: u8, data: &[u8], show: bool) -> Option<KVVec<u8>> {
        let r = self.sbio_query(op, data, show)?;
        if r.status != 0 {
            dev_err!(self.dev, "[sep2] enrol: {}: status {:#x}, not 0\n", proto::sbio_name(op), r.status);
            return None;
        }
        Some(r.data)
    }

    /// Stage 12 (Touch ID step 10c), after the bring-up and before the power goes off: an enrolment as 27.2 runs one,
    /// cancelled before any save; the SEP's xART writes held as at stage 7, so a write request ends it.
    /// 1. the contexts (enrol_contexts);
    /// 2. the credential (cred_open), kept open;
    /// 3. BEGIN_ENROL 0x03 and the images (enrol_images);
    /// 4. the cancel 0x05 once BEGIN_ENROL took (commandCancel in mode 3), Idle, the credential closed.
    fn run_enrol(&self) -> &'static str {
        let uid = match self.identity.as_ref() {
            Some(id) => id.uid,
            None => return "no identity file",
        };
        // stage 13 saves the enrolment: the owner's catacomb first, as Aurora's does
        if let Err(why) = self.enrol_contexts(uid, self.stage == 13) {
            return why;
        }
        let acm = match self.cred_open() {
            Ok(a) => a,
            Err(why) => return why,
        };
        if mesa::capture_arm(true).is_err() {
            self.cred_close(&acm, uid);
            return "the capture's frames could not be armed";
        }
        let (mut how, begun) = self.enrol_images(uid, &acm);
        if how == ENROL_COMPLETE && self.stage >= 13 {
            how = self.enrol_save(uid);
        } else if begun {
            let cancelled = self.enrol_sbio(proto::SBIO_CANCEL, &[], true).is_some();
            vinfo!(self.dev, "[sep2] enrol: the cancel {}\n", if cancelled { "answered status 0" } else { "NOT answered status 0" });
            if how == ENROL_COMPLETE {
                how = "the enrolment complete (0x08's done flag), cancelled before its save";
            } else if self.stage == 13 && cancelled {
                // a lab check needing no finger: the cancel leaves the user's component save-pending (stage 16,
                // build 41), so the fresh context's save path runs as after a completed enrolment, for a reload
                let saved = self.save_components(uid, false);
                vinfo!(self.dev, "[sep2] enrol: the cancelled enrolment's save: {}\n", saved);
            }
        }
        self.sensor_idle("stage 13's end");
        let _ = mesa::capture_arm(false);
        self.cred_close(&acm, uid);
        how
    }

    /// Stage 13 (Touch ID step 10d): the save after a complete enrolment, as biometrickitd drives it
    /// (performSpecificCommandGated cases 0x3c, 0x3d, 0x3f, 0x4a; its list: BiometricSupport
    /// `-[BiometricKitXPCServer getCatacombSaveListForComponents:list:]`): 0x6b's save-pending components but the
    /// master, in 0x6b's order, then the master (−1) last. Each gets 0x6c with its selector, the record's user at 8
    /// checked, the record handed to the host (hand_to_host), and once the host holds it on its disk, 0x37 with the
    /// same selector. Then the lockout record (0x70) to the host. The SEP's xART writes meanwhile go to the disk
    /// (write_served). Any refusal ends it. How it ended.
    ///
    /// 10d saved the master first and every active component: after a reboot the users' catacombs were refused as
    /// corrupted (0x6d 0x8002) and the master's taken, as a master kept before the users' saves would be.
    fn enrol_save(&self, uid: u32) -> &'static str {
        self.save_components(uid, true)
    }

    /// enrol_save's body. After an enrolment (`after_enrol`) the user's component must be save-pending. The components
    /// go in save_order: the save-pending ones, the master last.
    fn save_components(&self, uid: u32, after_enrol: bool) -> &'static str {
        if after_enrol {
            self.identities("after the enrolment");
        }
        let Some(comps) = self.components("before the save") else {
            return "0x6b before the save was not answered status 0";
        };
        let user = uid as i32;
        let pending = proto::COMPONENT_ACTIVE | proto::COMPONENT_SAVE_PENDING;
        if after_enrol && !comps.iter().any(|&(w, st)| w == user && st & pending == pending) {
            return "the user's component is not active and save-pending after the enrolment";
        }
        let Ok(order) = save_order(&comps) else {
            return "no memory";
        };
        for &(who, st) in comps.iter().filter(|c| !order.contains(&c.0)) {
            vinfo!(self.dev, "[sep2] save: component {} (state {:#x}): not saved\n", who, st);
        }
        for &who in order.iter() {
            if let Err(why) = self.save_one(who) {
                return why;
            }
        }
        let Some(r) = self.sbio_transact(proto::SBIO_LOCKOUT_SAVE, &[], true, proto::SAVE_MAX) else {
            return "0x70 was not answered";
        };
        if r.status != 0 || r.data.is_empty() {
            dev_err!(self.dev, "[sep2] save: 0x70: status {:#x}, {:#x} bytes\n", r.status, r.data.len());
            return "0x70 was not answered status 0 with a record";
        }
        if !self.hand_to_host(2, 0, &r.data) {
            return "the host did not keep the lockout record";
        }
        ENROL_SAVED
    }

    /// One component's catacomb saved: 0x6c with its selector, the record's user at 8 checked, the record handed to the
    /// host (hand_to_host), then 0x37 with the same selector.
    fn save_one(&self, who: i32) -> core::result::Result<(), &'static str> {
        let sel = proto::save_selector(who);
        let r = self.sbio_transact(proto::SBIO_SAVE_PREPARE, &sel, true, proto::SAVE_MAX).ok_or("0x6c was not answered")?;
        if r.status != 0 {
            dev_err!(self.dev, "[sep2] save: 0x6c for component {}: status {:#x}\n", who, r.status);
            return Err("0x6c was not answered status 0");
        }
        let named = r.data.get(8..12).map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        if named != Some(who) {
            dev_err!(self.dev, "[sep2] save: 0x6c for component {}: {:#x} bytes naming {:?} at 8\n", who, r.data.len(), named);
            return Err("0x6c's record names another user at 8");
        }
        if !self.hand_to_host(1, who, &r.data) {
            return Err("the host did not keep the catacomb");
        }
        self.enrol_sbio(proto::SBIO_SAVE_CONFIRM, &sel, true).ok_or("0x37 was not answered status 0")?;
        vinfo!(self.dev, "[sep2] save: component {}: its catacomb kept by the host and confirmed (0x37)\n", who);
        Ok(())
    }

    /// Stage 13: one record for the host to keep, at debugfs `apple-sep/save.bin`: a 16-byte header {"SAVE", u32
    /// the kind (1 a catacomb, 2 the lockout record), i32 the component (0 for the lockout record), u32 the length},
    /// then the record. The host writes it to its disk, syncs it, reads it back and answers at `save.ack` with the
    /// first 8 bytes of its SHA-256 as a decimal u64. True if that answer came within SAVE_ACK_MS and matches; the
    /// record is taken out of save.bin either way.
    fn hand_to_host(&self, kind: u32, who: i32, rec: &[u8]) -> bool {
        let (Some(f), Some(a)) = (self.save_file.as_ref(), self.ack_file.as_ref()) else {
            return false;
        };
        let h = sks::sha256(rec);
        let want = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        let mut v = KVVec::new();
        let made = v.reserve(16 + rec.len(), GFP_KERNEL).is_ok()
            && v.extend_from_slice(b"SAVE", GFP_KERNEL).is_ok()
            && v.extend_from_slice(&kind.to_le_bytes(), GFP_KERNEL).is_ok()
            && v.extend_from_slice(&who.to_le_bytes(), GFP_KERNEL).is_ok()
            && v.extend_from_slice(&(rec.len() as u32).to_le_bytes(), GFP_KERNEL).is_ok()
            && v.extend_from_slice(rec, GFP_KERNEL).is_ok();
        if !made {
            return false;
        }
        a.store(0, Relaxed);
        *f.lock() = v;
        let what = if kind == 1 { "a catacomb" } else { "the lockout record" };
        vinfo!(self.dev, "[sep2] save: {} (component {}), {:#x} bytes, sha256 {}: handed to the host\n", what, who, rec.len(), Hex(&h[..8]));
        let mut waited = 0;
        let ok = loop {
            let got = a.load(Relaxed);
            if got == want {
                break true;
            }
            if got != 0 {
                dev_err!(self.dev, "[sep2] save: the host's answer {:#018x} is not the record's {:#018x}\n", got, want);
                break false;
            }
            if waited >= SAVE_ACK_MS || !self.nap(SAVE_POLL_MS) {
                dev_err!(self.dev, "[sep2] save: no answer from the host in {} ms\n", waited);
                break false;
            }
            waited += SAVE_POLL_MS;
        };
        *f.lock() = KVVec::new();
        if ok {
            vinfo!(self.dev, "[sep2] save: {} kept by the host ({} ms)\n", what, waited);
        }
        ok
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
        vinfo!(self.dev, "[sep2] enrol: BEGIN_ENROL took; up to {} images, a finger on the sensor for each\n", ENROL_IMAGES);
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
                Relay::Next(took, _, _) => used += took as u32,
                Relay::Done(how) => {
                    vinfo!(self.dev, "[sep2] enrol: {} images, {} used\n", i + 1, used);
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
        vinfo!(self.dev, "[sep2] enrol: {} images, {} used\n", ENROL_IMAGES, used);
        ("the image limit reached before the done flag", true)
    }

    /// 0x6b's components and their states, each logged with `when`.
    fn components(&self, when: &str) -> Option<KVec<(i32, u32)>> {
        let states = self.enrol_sbio(0x6b, &[], true)?;
        let mut v = KVec::new();
        for c in states.chunks_exact(8) {
            let who = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            let st = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            vinfo!(self.dev, "[sep2] components: {}: {}: state {:#x}\n", when, who, st);
            v.push((who, st), GFP_KERNEL).ok()?;
        }
        Some(v)
    }

    /// Stage 14: one saved catacomb back to the SEP, by its component's state (0x6b read before it): an active
    /// component is not loaded; any other, or an unlisted one, gets 0x6d with the record. Status 0 takes; 0x8002 or
    /// 0x101 takes if 0x6b then shows the component active. Whether it took.
    fn load_catacomb(&self, who: i32, rec: &[u8]) -> bool {
        let Some(before) = self.components("before its load") else {
            return false;
        };
        let st = before.iter().find(|c| c.0 == who).map(|c| c.1);
        if st.is_some_and(|st| st & proto::COMPONENT_ACTIVE != 0) {
            vinfo!(self.dev, "[sep2] match: component {} already active (state {:#x}): its catacomb not loaded\n", who, st.unwrap_or(0));
            return true;
        }
        let status = match self.sbio_transact(proto::SBIO_LOAD_CATACOMB, rec, true, 0) {
            Some(r) => r.status,
            None => {
                dev_err!(self.dev, "[sep2] match: 0x6d for component {} was not answered\n", who);
                return false;
            }
        };
        vinfo!(self.dev, "[sep2] match: 0x6d for component {} (state {:?}, {:#x} bytes): status {:#x}\n", who, st, rec.len(), status);
        if status == 0 {
            return true;
        }
        if proto::load_refused(status) {
            dev_err!(self.dev, "[sep2] match: component {}'s catacomb refused as corrupted ({:#x}, biometrickitd's 0x10D)\n", who, status);
            return false;
        }
        if !proto::LOAD_RECHECK.contains(&status) {
            return false;
        }
        let after = self.components("after its load's status");
        let now = after.as_ref().and_then(|v| v.iter().find(|c| c.0 == who).map(|c| c.1));
        now.is_some_and(|st| st & proto::COMPONENT_ACTIVE != 0)
    }

    /// Stage 14 (Touch ID step 10e), after a reboot: the records stage 13 saved loaded back (performSpecificCommandGated
    /// cases 0x40 and 0x4b) between the calibration and the second bring-up (run_mesa): each catacomb by its
    /// component's state (load_catacomb, the master's first; the master's and the user's must take, another
    /// component's may not), then the lockout record through 0x71 (a refusal logged and passed), then the identities
    /// the SEP lists (0x7a, and the user's, 0x6e).
    fn match_load(&self) -> core::result::Result<(), &'static str> {
        let (Some(saved), Some(id)) = (self.saved.as_ref(), self.identity.as_ref()) else {
            return Err("no saved records or identity");
        };
        let uid = id.uid;
        for (kind, who, rec) in saved.recs.iter() {
            if *kind == 1 {
                if self.load_catacomb(*who, rec) {
                    continue;
                }
                if *who == proto::USER_SYSTEM || *who == uid as i32 {
                    return Err("the master's or the user's saved catacomb did not take (0x6d)");
                }
                // another component (501): the match is the user's, so it goes on
                vinfo!(self.dev, "[sep2] match: component {}'s catacomb did not take; going on\n", who);
                continue;
            }
            match self.sbio_transact(proto::SBIO_LOAD_LOCKOUT, rec, true, 0) {
                Some(r) if r.status == 0 => vinfo!(self.dev, "[sep2] match: the lockout record ({:#x} bytes) loaded\n", rec.len()),
                // builds 30-32: 0xffffffff, after the user's catacomb took; the match goes on without it (what the SEP
                // then counts is not known), and the save after the match keeps a new record
                Some(r) => dev_err!(self.dev, "[sep2] match: the lockout record refused (0x71: status {:#x}); going on\n", r.status),
                None => return Err("the lockout record's load was not answered"),
            }
        }
        self.identities("after the load");
        Ok(())
    }

    /// 0x7a's identity records and, once the load's ops may go out (stage 14), 0x6e's list of the identity's user's,
    /// logged with `when`: each one's count and uids (the UUIDs never logged).
    fn identities(&self, when: &str) {
        let uid = self.identity.as_ref().map(|id| id.uid);
        if let (Some(uid), true) = (uid, proto::LOAD_ARMED.load(core::sync::atomic::Ordering::Relaxed)) {
            match self.sbio_query(proto::SBIO_IDENTITIES_LIST, &uid.to_le_bytes(), false) {
                Some(r) if r.status == 0 => {
                    let n = r.data.len() / proto::IDENTITY_LIST_REC;
                    vinfo!(self.dev, "[sep2] match: {}: uid {} has {} identities (0x6e, {:#x} bytes)\n", when, uid, n, r.data.len());
                    for rec in r.data.chunks_exact(proto::IDENTITY_LIST_REC) {
                        let u = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                        vinfo!(self.dev, "[sep2] match: {}: 0x6e lists an identity of uid {}\n", when, u);
                    }
                }
                Some(r) => vinfo!(self.dev, "[sep2] match: {}: 0x6e status {:#x}\n", when, r.status),
                None => vinfo!(self.dev, "[sep2] match: {}: 0x6e not answered\n", when),
            }
        }
        match self.sbio_query(0x7a, &[], false) {
            Some(r) if r.status == 0 => {
                vinfo!(self.dev, "[sep2] match: {}: {} identity records\n", when, r.data.len() / 40);
                for rec in r.data.chunks_exact(40) {
                    let u = i32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                    vinfo!(self.dev, "[sep2] match: {}: an identity of uid {}\n", when, u);
                }
            }
            Some(r) => vinfo!(self.dev, "[sep2] match: {}: 0x7a status {:#x}\n", when, r.status),
            None => vinfo!(self.dev, "[sep2] match: {}: 0x7a not answered\n", when),
        }
    }

    /// Stage 14's match, after the second bring-up: the identities and the components' states logged (0x7a, 0x6b; the
    /// user's must be active), then, the enrolment's credential open (cred_open), one unlock match as
    /// commandStartMatch and asyncCaptureHandler run it (no SBIO at its start; flags 1 and the user in each 0x06):
    /// per touch 0x23, 0x06, 0x65, 0x07, and 0x09 for an image usable for a match, until 0x09 names a user or
    /// MATCH_IMAGES touches; 0x22 after each. A refused 0x09 opens the credential again for the next touch, a second
    /// selects the enrolment's contexts (enrol_contexts). Then the save after the match: each save-pending component
    /// (0x6c, the host, 0x37) and the lockout record (0x70) to the host; the credential closed. How it ended.
    fn run_match(&self) -> &'static str {
        let Some(id) = self.identity.as_ref() else {
            return "no identity";
        };
        let uid = id.uid;
        self.identities("after the second bring-up");
        let Some(states) = self.components("after the load") else {
            return "0x6b after the load was not answered status 0";
        };
        if !states.iter().any(|&(w, st)| w == uid as i32 && st & proto::COMPONENT_ACTIVE != 0) {
            return "the user's component is not active after the load";
        }
        // build 31, without it: 0x09 answered status 1 on an image usable for a match
        let mut acm = match self.cred_open() {
            Ok(a) => a,
            Err(why) => return why,
        };
        if mesa::capture_arm(true).is_err() {
            self.cred_close(&acm, uid);
            return "the capture's frames could not be armed";
        }
        let mut how = "no match in 5 touches";
        let mut matched = false;
        let mut rung = 0;
        for i in 0..MATCH_IMAGES {
            let (mut img, ready, at) = match self.capture_image(ENROL_CAPTURE_MS) {
                Ok(v) => v,
                Err(why) => {
                    how = why;
                    break;
                }
            };
            let ticks = mesa::ticks();
            self.image_check_log(&img, ready, at, i == 0);
            let init = proto::image_init_match(0, ticks, proto::MATCH_UNLOCK, uid);
            let head = self.relay_head(&img, &init);
            img.fill(0);
            drop(img);
            let a = match head {
                Ok(a) => a,
                Err(why) => {
                    how = why;
                    break;
                }
            };
            vinfo!(self.dev, "[sep2] match: image {}: error {}, for a match {}, assessment {}, feedback {}\n", i, a.err, a.for_match, a.assessment, a.feedback);
            if a.for_match != 0 {
                match self.enrol_sbio(proto::SBIO_MATCH_RESULT, &[], false).map(|v| proto::parse_match(&v)) {
                    // build 32: status 1 with the credential opened before the touches, 0x16 after the contexts;
                    // a refusal reopens the credential for the next touch, a second selects the contexts
                    None if rung == 0 => {
                        rung = 1;
                        self.cred_close(&acm, uid);
                        acm = match self.cred_open() {
                            Ok(a) => a,
                            Err(why) => {
                                how = why;
                                break;
                            }
                        };
                        vinfo!(self.dev, "[sep2] match: 0x09 refused; the credential opened again, the next touch\n");
                    }
                    None if rung == 1 => {
                        rung = 2;
                        if let Err(why) = self.enrol_contexts(uid, false) {
                            how = why;
                            break;
                        }
                        vinfo!(self.dev, "[sep2] match: 0x09 refused again; the contexts selected as for the enrolment, the next touch\n");
                    }
                    None => how = "0x09 was not answered status 0",
                    Some(None) => how = "0x09's reply is not 0xca2 bytes",
                    Some(Some(m)) => {
                        let user = m.user as i32;
                        vinfo!(self.dev, "[sep2] match: image {}: 0x09 names user {} (retry {})\n", i, user, m.retry);
                        if m.user != u32::MAX {
                            matched = true;
                            how = if user == uid as i32 { "matched: 0x09 named the enrolled user" } else { "0x09 named another user" };
                        }
                    }
                }
            }
            if self.enrol_sbio(proto::SBIO_BG_OPS, &[], false).is_none() {
                how = "0x22 was not answered status 0";
                break;
            }
            if matched || how.starts_with("0x09") {
                break;
            }
            if mesa::command(mesa::T_IDLE).is_err() || !self.nap(ENROL_LIFT_MS) {
                how = "Idle after an image was not sent, or the driver is going away";
                break;
            }
        }
        self.sensor_idle("stage 14's end");
        let _ = mesa::capture_arm(false);
        let saved = self.save_components(uid, false);
        vinfo!(self.dev, "[sep2] match: the save after it: {}\n", saved);
        self.cred_close(&acm, uid);
        how
    }

    /// The contexts an enrolment needs before BEGIN_ENROL (run_enrol, bio.rs), as biometrickitd's startEnrollOperation:
    /// and loadCatacombForComponent: decide them (rda BiometricSupport 27.2 0x238a2229c, 0x238a2c490; touchid-lift.md
    /// §3): 0x2d (NoCatacomb), the kext's own 0x2b after it, only for a component with nothing loaded. The master (−1):
    /// 0x2d unless 0x6b shows it active, and it must be active after. The user: active (their kept catacomb loaded)
    /// takes BEGIN_ENROL as it is, so the enrolment adds a finger; known to the SEP but not loaded is refused (LOAD
    /// it first: a fresh context would start it anew); unknown gets 0x2d and 0x2b, the path the lab's first enrolments
    /// took (macOS sends nothing there: BEGIN_ENROL creates it). With `export_owner` (stage 13's lab run), the owner's
    /// catacomb (501, active in a fresh system context, not save-pending: 0x3 in 10d) is saved between the two as any
    /// other (save_one); biometrickitd's rule never saves it there (save_order), Aurora's driver does.
    fn enrol_contexts(&self, uid: u32, export_owner: bool) -> core::result::Result<(), &'static str> {
        let user = uid as i32;
        let Some(mut states) = self.components("before the enrolment") else {
            return Err("0x6b before the enrolment was not answered status 0");
        };
        let state = |v: &KVec<(i32, u32)>, w: i32| v.iter().find(|c| c.0 == w).map(|c| c.1);
        if !state(&states, proto::USER_SYSTEM).is_some_and(|st| st & proto::COMPONENT_ACTIVE != 0) {
            if self.enrol_sbio(proto::SBIO_SELECT_CONTEXT, &proto::USER_SYSTEM.to_le_bytes(), true).is_none() {
                return Err("0x2d for the system context was not answered status 0");
            }
            states = self.components("after the system context").ok_or("0x6b after the system context was not answered status 0")?;
            if !state(&states, proto::USER_SYSTEM).is_some_and(|st| st & proto::COMPONENT_ACTIVE != 0) {
                return Err("the master component is not active after the system context");
            }
        }
        if export_owner {
            match state(&states, proto::USER_OWNER) {
                Some(st) if st & proto::COMPONENT_ACTIVE != 0 => {
                    vinfo!(self.dev, "[sep2] enrol: the owner's catacomb (state {:#x}) saved in the fresh context\n", st);
                    self.save_one(proto::USER_OWNER)?;
                }
                st => vinfo!(self.dev, "[sep2] enrol: the owner's component is not active ({:?}): not saved\n", st),
            }
        }
        match state(&states, user) {
            Some(st) if st & proto::COMPONENT_ACTIVE != 0 => {
                vinfo!(self.dev, "[sep2] enrol: uid {}'s component is active (state {:#x}): the enrolment adds to it\n", uid, st);
            }
            Some(st) if st & proto::COMPONENT_KNOWN != 0 => {
                return Err("the user's component is known to the SEP but not loaded: its catacomb goes back first");
            }
            _ => {
                if self.enrol_sbio(proto::SBIO_SELECT_CONTEXT, &user.to_le_bytes(), true).is_none() {
                    return Err("0x2d for the user was not answered status 0");
                }
                if self.enrol_sbio(proto::SBIO_PROTECTED_CONFIG, &user.to_le_bytes(), true).is_none() {
                    return Err("0x2b for the user was not answered status 0");
                }
            }
        }
        Ok(())
    }

    /// Stage 17: the SEP's last lock state for `uid` (its request 1), if it sent one.
    pub(crate) fn lock_state(&self, uid: u32) -> Option<u16> {
        let st = self.state.lock();
        st.locks[..st.n_locks].iter().find(|l| l.0 == uid).map(|l| l.1)
    }

    /// The sensor idled, as AppleMesa at an operation's end: Idle (`_handleCMD` case 1), then the status every
    /// CAPTURE_POLL_MS for up to STEP_MS until it reads idle (handleStateMachine waits as long for the Idle's interrupt,
    /// event 0x50); failing that, its force-idle as after a lift (10 ms, Sleep, 20 ms). Logs which took effect. The
    /// last status read, or None when none was.
    pub(crate) fn sensor_idle(&self, why: &str) -> Option<mesa::Status> {
        self.capture_armed.store(false, Relaxed);
        let first = mesa::status().ok()?;
        if first.sane() && first.state() == mesa::STATE_IDLE {
            return Some(first);
        }
        if mesa::command(mesa::T_IDLE).is_err() {
            dev_err!(self.dev, "[sep2] idle ({}): Idle was not sent ({})\n", why, Hex(&first.0));
            return Some(first);
        }
        let mut waited = 0u32;
        let mut s = first;
        while waited < mesa::STEP_MS && self.nap(CAPTURE_POLL_MS) {
            waited += CAPTURE_POLL_MS;
            s = mesa::status().ok()?;
            if s.sane() && s.state() == mesa::STATE_IDLE {
                vinfo!(self.dev, "[sep2] idle ({}): Idle took effect in {} ms ({} before, {} after)\n", why, waited, Hex(&first.0), Hex(&s.0));
                return Some(s);
            }
        }
        vinfo!(self.dev, "[sep2] idle ({}): Idle did not take effect in {} ms ({} before, {} after): Sleep\n", why, waited, Hex(&first.0), Hex(&s.0));
        if !self.nap(10) || mesa::command(mesa::T_SLEEP).is_err() || !self.nap(20) {
            return Some(s);
        }
        s = mesa::status().ok()?;
        vinfo!(self.dev, "[sep2] idle ({}): after Sleep: {} (state {})\n", why, Hex(&s.0), s.state());
        Some(s)
    }

    /// Between touches, as AppleMesa does it (BS272, touchid-lift.md §1): with the finger still on after an image
    /// ([11] bit 1), PauseCapture, then the status read every CAPTURE_POLL_MS until the bit clears; then, the sensor
    /// not idle, 10 ms, Sleep and 20 ms, so the next StartCapture finds it idle. No Idle between touches. `tick` runs
    /// every 100 ms of the wait (the authenticator's keepalive) and stops it by returning false. Err CAPTURE_CANCELLED on
    /// a cancel, the driver going away or `tick`, CAPTURE_NO_IMAGE when the finger stays the whole window.
    pub(crate) fn wait_lift(&self, window: u32, tick: &mut dyn FnMut() -> bool) -> core::result::Result<(), &'static str> {
        let mut s = mesa::status().map_err(|_| "the status was not read before the lift")?;
        if s.finger() {
            mesa::command(mesa::T_PAUSE_CAPTURE).map_err(|_| "PauseCapture was not sent")?;
            vinfo!(self.dev, "[sep2] lift: the finger still on ({}): PauseCapture\n", Hex(&s.0));
            let mut waited = 0u32;
            let mut last = None;
            let mut dropped = 0u32;
            loop {
                if self.bio_cancel.load(Relaxed) || !self.nap(CAPTURE_POLL_MS) {
                    return Err(CAPTURE_CANCELLED);
                }
                waited += CAPTURE_POLL_MS;
                if waited % 100 == 0 && !tick() {
                    return Err(CAPTURE_CANCELLED);
                }
                s = mesa::status().map_err(|_| "the status was not read during the lift")?;
                if last != Some((s.state(), s.0[11])) {
                    last = Some((s.state(), s.0[11]));
                    vinfo!(self.dev, "[sep2] lift: at {} ms: {} (state {}, [11] {:#04x})\n", waited, Hex(&s.0), s.state(), s.0[11]);
                }
                // An image the sensor took meanwhile is read and dropped ("Paused state, dropping image"): left
                // unread it holds the status at data ready with the finger bit set, and the lift never shows
                // (build 54: 6.6 s of one status after the finger was gone).
                if s.state() == mesa::STATE_DATA_READY && s.count() as usize >= mesa::IMAGE_LEN_SHORT {
                    let n = if s.count() as usize >= mesa::IMAGE_LEN { mesa::IMAGE_LEN } else { mesa::IMAGE_LEN_SHORT };
                    let mut img = mesa::read_image(n).map_err(|_| "an image read while paused failed")?;
                    img.fill(0);
                    dropped += 1;
                    continue;
                }
                if !s.finger() {
                    vinfo!(self.dev, "[sep2] lift: the finger off at {} ms, {} images dropped while paused\n", waited, dropped);
                    break;
                }
                if waited >= window {
                    return Err(CAPTURE_NO_IMAGE);
                }
            }
        }
        if s.state() != mesa::STATE_IDLE {
            if !self.nap(10) {
                return Err(CAPTURE_CANCELLED);
            }
            mesa::command(mesa::T_SLEEP).map_err(|_| "Sleep was not sent")?;
            if !self.nap(20) {
                return Err(CAPTURE_CANCELLED);
            }
        }
        Ok(())
    }

    /// The part of an image's relay a match and an enrolment share (asyncCaptureHandler): 0x23, 0x06 with `init`,
    /// 0x65 (the image, in two packets), 0x07; the assessment.
    fn relay_head(&self, img: &[u8], init: &[u8]) -> core::result::Result<proto::Assessment, &'static str> {
        if img.len() != mesa::IMAGE_LEN {
            return Err("an image of 0x4800 bytes: the SEP's capture buffer for this sensor is 0x7200");
        }
        if self.enrol_sbio(proto::SBIO_IMAGE_PREPARE, &[], false).is_none() {
            return Err("0x23 was not answered status 0");
        }
        if self.enrol_sbio(proto::SBIO_IMAGE_INIT, init, false).is_none() {
            return Err("0x06 was not answered status 0");
        }
        if self.enrol_sbio(proto::SBIO_CAPTURE, img, false).is_none() {
            return Err("0x65 (the image) was not answered status 0");
        }
        let Some(a) = self.enrol_sbio(proto::SBIO_IMAGE_ASSESS, &[], false) else {
            return Err("0x07 was not answered status 0");
        };
        proto::parse_assessment(&a).ok_or("0x07's reply is shorter than 0x89 bytes and its extension")
    }

    /// One image relayed as asyncCaptureHandler relays it; what came of it.
    fn enrol_relay(&self, i: u32, img: &[u8], ticks: u64) -> Relay {
        let a = match self.relay_head(img, &proto::image_init(0, ticks)) {
            Ok(a) => a,
            Err(why) => return Relay::Done(why),
        };
        vinfo!(
            self.dev,
            "[sep2] enrol: image {}: error {}, for the enrolment {}, for a match {}, assessment {}, feedback {}, purpose {}, outliers {}, dirt {}\n",
            i, a.err, a.for_enrol, a.for_match, a.assessment, a.feedback, a.purpose, a.outliers, a.dirt
        );
        let mut end = None;
        let mut progress = 0;
        if a.for_enrol != 0 {
            match self.enrol_sbio(proto::SBIO_ENROL_RESULT, &[], false).map(|v| proto::parse_enrol_result(&v)) {
                None => end = Some("0x08 was not answered status 0"),
                Some(None) => end = Some("0x08's reply is not 0xc98 bytes"),
                Some(Some(r)) => {
                    let (placed, identity, user) = (r.placement != 0, r.identity != 0, r.user as i32);
                    vinfo!(
                        self.dev,
                        "[sep2] enrol: image {}: done {}, error {:#x}, progress {}, placement {}, identity {} (user {})\n",
                        i, r.done, r.err, r.progress, placed, identity, user
                    );
                    progress = r.progress;
                    if r.done != 0 || r.err == proto::ENROL_ERR_END {
                        end = Some(if r.err == 0 { ENROL_COMPLETE } else { "the enrolment ended with an error" });
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
            None => Relay::Next(a.for_enrol != 0, progress, a.feedback),
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
        vinfo!(
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
        vinfo!(self.dev, "[sep2] mesa: {}: {:#x} bytes read\n", what, n);
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
    /// From stage 12 the calibration follows (mesa_calibrate), then the same steps again, as macOS runs them after it.
    fn run_mesa(&self) -> bool {
        if !mesa::present() {
            if self.stage < STAGE_DAILY {
                return self.mesa_end("no sensor bound (spi2-on.ko power=1 first)");
            }
            vinfo!(self.dev, "[sep2] mesa: no sensor bound yet: waiting up to {} ms for its driver\n", SENSOR_WAIT_MS);
            if !mesa::wait_present(SENSOR_WAIT_MS) {
                return self.mesa_end("no sensor bound: its DT node (spi2's sensor@0) or its driver is missing");
            }
            vinfo!(self.dev, "[sep2] mesa: the sensor bound\n");
        }
        if !self.mesa_pass(false) {
            return false;
        }
        let mut loaded = Ok(());
        if self.stage >= 12 {
            if !self.mesa_calibrate() {
                return false;
            }
            // build 32: loaded after the second bring-up, the records took but 0x09 refused every usable image
            if self.stage == 14 {
                loaded = self.match_load();
            }
            if !self.mesa_pass(true) {
                return false;
            }
            vinfo!(self.dev, "[sep2] mesa: the bring-up run again on the calibration, as resetSensorAndLoadPatch(4) runs it\n");
        }
        if self.stage == 11 {
            let how = self.run_capture();
            vinfo!(self.dev, "[sep2] capture: {}\n", how);
            self.state.lock().sbio.capture = Some(how);
        }
        if (12..=13).contains(&self.stage) {
            let mut how = self.run_enrol();
            vinfo!(self.dev, "[sep2] enrol: {}\n", how);
            // build 34: the records loaded after a reboot listed no identity; a match in the saving boot tells
            // whether the match or the reload loses it
            if self.stage == 13 && how == ENROL_SAVED {
                self.identities("after the save");
                how = self.run_match();
                vinfo!(self.dev, "[sep2] match: in the saving boot: {}\n", how);
            }
            self.state.lock().sbio.enrol = Some(how);
        }
        if self.stage == 14 {
            let how = match loaded {
                Ok(()) => self.run_match(),
                Err(why) => why,
            };
            vinfo!(self.dev, "[sep2] match: {}\n", how);
            self.state.lock().sbio.enrol = Some(how);
        }
        let off = mesa::power(false).is_ok();
        vinfo!(self.dev, "[sep2] mesa: the bring-up done as on macOS; the power {}\n", if off { "off" } else { "not switched" });
        self.state.lock().sbio.mesa = Some("the bring-up done: the session, the patch, the parameters, the module serial");
        true
    }

    /// Stage 12 on, after the first bring-up: the factory calibration as biometrickitd starts it (performSpecificCommandGated
    /// case 0x20 → setCalibrationData 0xfffffe0009ab9210, the source FDR): SBIO 0x5B {u32 3, the record}, in packets,
    /// then 0x63's 0x1c-byte info. The SEP refuses every image from an uncalibrated sensor: 0x65 answered status 1
    /// (2026-11-08, build 26). macOS then resets the sensor and loads the patch again (resetSensorAndLoadPatch(4, 0)
    /// 0xfffffe0009abcb18: run_mesa's steps again, patch type 4 asked as 2, the module serial number since the source
    /// is not 4 or 5), and sends the Mac's serial number as 0x48 only when it has 12 characters
    /// (sendDeviceSerialNumberToSbio 0xfffffe0009abd280): this Mac's has 10, so it is skipped as macOS skips it.
    fn mesa_calibrate(&self) -> bool {
        let Some(cal) = self.calibration.as_ref() else {
            return self.mesa_end("no calibration input");
        };
        let mut req = KVVec::new();
        if req.extend_from_slice(&proto::CALIBRATION_FDR.to_le_bytes(), GFP_KERNEL).is_err()
            || req.extend_from_slice(cal, GFP_KERNEL).is_err()
        {
            return self.mesa_end("no memory for the calibration's request");
        }
        let Some(r) = self.sbio_transact(proto::SBIO_LOAD_CALIBRATION, &req, false, 0) else {
            return self.mesa_end("SBIO 0x5B was not answered");
        };
        match r.status {
            0 => {}
            proto::CALIBRATION_BAD_SIGNATURE => return self.mesa_end("SBIO 0x5B: the calibration's signature is not valid (0x12e)"),
            proto::CALIBRATION_BAD_SERIAL => {
                return self.mesa_end("SBIO 0x5B: the calibration's serial number is not the sensor's (0x12f)")
            }
            s => {
                dev_err!(self.dev, "[sep2] mesa: SBIO 0x5B: status {:#x}\n", s);
                return self.mesa_end("SBIO 0x5B was refused");
            }
        }
        let Some(r) = self.mesa_sbio(proto::SBIO_CALIBRATION_INFO, &[], Some(proto::CALIBRATION_INFO_LEN), false) else {
            return self.mesa_end("SBIO 0x63 did not give the calibration's 0x1c-byte info");
        };
        let v = u32::from_le_bytes([r.data[0x10], r.data[0x11], r.data[0x12], r.data[0x13]]);
        vinfo!(self.dev, "[sep2] mesa: the calibration loaded ({:#x} bytes, FDR), its version {}\n", req.len(), v);
        true
    }

    /// run_mesa's steps 1-8, once; false after mesa_end. `again`: a reset after the bring-up, which sends 0x19 where
    /// the first sends 0x80 (resetSensor 0xfffffe0009ac0674: the ID once per boot, 0x19 once the sensor's state is not
    /// 0; without it the SEP refuses the next key exchange 0x15, status 1, 2026-11-08 build 27).
    fn mesa_pass(&self, again: bool) -> bool {
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
        if again {
            if self.mesa_sbio(proto::SBIO_SENSOR_RESET, &[], None, true).is_none() {
                return self.mesa_end("SBIO 0x19 was not answered status 0");
            }
        } else if self.mesa_sbio(0x80, &mesa::SENSOR_ID.to_le_bytes(), None, true).is_none() {
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
        vinfo!(self.dev, "[sep2] mesa: the patch: {:#x} bytes, sha256 {}\n", r.data.len(), Hex(&h[..8]));
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
        vinfo!(self.dev, "[sep2] mesa: the patch is loaded, version {:#x}\n", s.patch_version());

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
            vinfo!(self.dev, "[sep2] mesa: SBIO 0x6A gave nothing: skipped, as macOS skips it\n");
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
        vinfo!(self.dev, "[sep2] discovery: {} endpoints in {} messages\n", st.n_apps, st.rx_total);
        for a in &st.apps[..st.n_apps] {
            vinfo!(
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
        vinfo!(
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
            vinfo!(self.dev, "[sep2] step {}/{}: security mode {} (macOS 14.8.3 got 3)\n", i, total, r.data);
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
        vinfo!(self.dev, "[sep2] {}: all {} steps acked\n", name, steps.len());
        true
    }

    fn bringup(&self) {
        vinfo!(self.dev, "[sep2] stage {}: waiting for the discovery\n", self.stage);
        if !self.wait_discovery() {
            dev_err!(
                self.dev,
                "[sep2] no answer to the registration within {} ms (m1n1 older than r73, or an earlier registration this boot): nothing more is sent\n",
                FIRST_RESPONSE_MS
            );
            self.bio_settle(false);
            self.summary();
            return;
        }
        self.log_discovery();

        let ok = 'seq: {
            if self.stage == 0 {
                vinfo!(self.dev, "[sep2] stage 0: step 1 only, nothing more is sent\n");
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
            if self.stage >= 17 {
                self.keys_early();
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
            if self.stage >= 15 {
                self.bio_settle(true);
                dev_info!(self.dev, "[sep2] bio: /dev/apple-sep-bio is ready\n");
            }
            true
        };
        if !ok {
            self.bio_settle(false);
            dev_err!(self.dev, "[sep2] stage {} STOPPED; Touch ID is not available this boot\n", self.stage);
        }
        vinfo!(
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

    /// Stage 15: the bring-up's end for bio.rs's WAIT, ready or stopped. Set under `state`'s lock, which WAIT holds
    /// from its check until it sleeps, so its wake is not lost.
    fn bio_settle(&self, ready: bool) {
        if self.stage < 15 {
            return;
        }
        let st = self.state.lock();
        if ready {
            self.bio_ready.store(true, Relaxed);
        } else {
            self.bio_stopped.store(true, Relaxed);
        }
        drop(st);
        self.wq.notify_all();
    }

    fn summary(&self) {
        let rx = self.rx_total();
        vinfo!(
            self.dev,
            "[sep2] summary: {} sent, {} received ({} dropped), {} xART requests held, {} xART writes refused, {} written to the disk\n",
            self.tx_count.load(Relaxed),
            rx,
            self.rx.lost(),
            self.xarm_held.load(Relaxed),
            self.xarm_refused.load(Relaxed),
            self.xarm_written.load(Relaxed)
        );
        if self.stage >= 3 {
            if let Some(s) = self.xart.lock().as_ref() {
                vinfo!(
                    self.dev,
                    "[sep2] xART: the .gl copy in memory, never written, holds {} records, revision {:#x}\n",
                    s.used(),
                    s.rev()
                );
            }
            let st = self.state.lock();
            vinfo!(
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
                vinfo!(self.dev, "[sep2] xART: it stopped at {}\n", why);
            }
        }
        if self.stage >= 6 {
            let k = self.state.lock().sks;
            vinfo!(
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
                vinfo!(self.dev, "[sep2] identity: {}\n", k.identity.unwrap_or("never began"));
            }
            if self.stage >= 8 {
                let b = self.state.lock().sbio;
                vinfo!(
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
                vinfo!(self.dev, "[sep2] mesa: {}\n", m.unwrap_or("never began"));
            }
            if self.stage >= 10 {
                let c = self.state.lock().sbio.cred;
                vinfo!(self.dev, "[sep2] credential: {}\n", c.unwrap_or("never began"));
            }
            if self.stage == 11 {
                let c = self.state.lock().sbio.capture;
                vinfo!(self.dev, "[sep2] capture: {}\n", c.unwrap_or("never began"));
            }
            if (12..=14).contains(&self.stage) {
                let c = self.state.lock().sbio.enrol;
                let what = if self.stage == 14 { "match" } else { "enrol" };
                vinfo!(self.dev, "[sep2] {}: {}\n", what, c.unwrap_or("never began"));
            }
        }
        let b = self.bufs.lock();
        for app in BUF_APPS {
            let Some(i) = app_index(app) else { continue };
            if let Some(p) = &b.ool[i] {
                let (ni, fi) = nonzero(&p.inbound, 0, app.ool_size());
                let (no, fo) = nonzero(&p.outbound, 0, app.ool_size());
                vinfo!(
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
                vinfo!(self.dev, "[sep2] CINP, the SEP's panic channel, is still zero\n");
            }
        }
    }

    fn remove(&self) {
        self.closing.store(true, Relaxed);
        self.wq.notify_all();
        // under `fido_tx`, so no send is under way when the device goes
        let f = {
            let _tx = self.fido_tx.lock();
            self.fido_dev.swap(core::ptr::null_mut(), CR)
        };
        if !f.is_null() {
            // SAFETY: `f` is the device apple_sep_fido_create made, destroyed once; its callbacks end with it.
            unsafe { fido::ffi::apple_sep_fido_destroy(f) };
        }
        // no new open, then the operation in flight ends (its waits see `closing`); the Service's Arc goes with it
        let service = self.service.lock().take();
        drop(service);
        drop(self.bio_op.lock());
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

impl WorkItem<2> for SepData {
    type Pointer = Arc<SepData>;

    fn run(this: Arc<SepData>) {
        if this.closing.load(Relaxed) {
            return;
        }
        this.fido_run();
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
        VERBOSE.store(module_parameters::verbose.value() != 0, core::sync::atomic::Ordering::Relaxed);
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
            .optional();
        let daily = stage.is_none();
        let stage = stage.unwrap_or(STAGE_DAILY);
        if daily {
            vinfo!(dev, "[sep2] no apple,sep2-stage: Touch ID's daily flow (stage {})\n", STAGE_DAILY);
        }
        if stage > STAGE_MAX {
            dev_err!(dev, "[sep2] stage {} is not 0-{}\n", stage, STAGE_MAX);
            return Err(EINVAL);
        }
        // Stage 3's `.gl` is on the internal disk, which may come up after this probe (the node enabled at boot)
        if stage >= 3 && disk::Extents::from_param().is_ok_and(|p| p.is_none()) {
            if let Err(e) = disk::wait(dev) {
                if e == EPROBE_DEFER {
                    vinfo!(dev, "[sep2] the iBoot System Container is not up yet: attaching when it comes\n");
                }
                return Err(e);
            }
        }

        // The SEP DART's window starts above 4 GiB (0x100_0000_4000).
        // SAFETY: probe has not allocated DMA memory for this device yet.
        unsafe { pdev.dma_set_mask_and_coherent(dma::DmaMask::new::<42>())? };

        let data = SepData::new(pdev, stage)?;
        if stage >= 7 {
            sks::IDENTITY_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 17 && module_parameters::fido.value() != 0 {
            sks::KEYS_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
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
        if stage >= 14 {
            proto::LOAD_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        if stage >= 13 {
            proto::SAVE_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        *data.mbox.lock() = Some(Mailbox::new_byname(dev, c"mbox", data.clone())?);
        // Stage 15: the node from probe, so a client started before the bring-up ends finds it and WAITs (bio.rs)
        if stage >= 15 {
            match bio::Service::new(data.clone()) {
                Ok(svc) => *data.service.lock() = Some(svc),
                Err(e) => {
                    *data.mbox.lock() = None;
                    dev_err!(dev, "[sep2] bio: /dev/apple-sep-bio not registered ({:?}); not probing\n", e);
                    return Err(e);
                }
            }
        }

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
        if self.0.stage >= 13 {
            disk::close();
        }
    }
}

module_platform_driver! {
    type: SepDriver,
    name: "apple_sep",
    description: "Apple SEP: Touch ID lab driver (warm attach, enables, xART service, key store, SBIO, the sensor, enrolment, match) and /dev/apple-sep-bio",
    license: "GPL",
    params: {
        verbose: u32 {
            default: 0,
            description: "The lab's logging: every message, SBIO transaction and the sensor's status (1)",
        },
        fido: u32 {
            default: 1,
            description: "The FIDO2 authenticator, its keys in the SEP and user presence by a Touch ID touch (1, the default; 0 off)",
        },
    },
}

/// The authenticator's plain atomics (its HID device, its handle).
const CR: core::sync::atomic::Ordering = core::sync::atomic::Ordering::Relaxed;

/// fido.c's callback: one packet from hidraw's writer.
unsafe extern "C" fn fido_rx(ctx: *mut core::ffi::c_void, pkt: *const u8) {
    // SAFETY: `ctx` is the SepData fido_start gave, which lives only in an Arc (SepData::new), so it is that Arc's
    // `as_ptr`; the Arc outlives the HID device, which remove() destroys before the driver's reference goes. `pkt`
    // is 64 bytes.
    let (d, p) = unsafe { (kernel::sync::ArcBorrow::<SepData>::from_raw(ctx.cast::<SepData>()), &*pkt.cast::<[u8; 64]>()) };
    if !d.closing.load(Relaxed) {
        SepData::fido_packet(&d.into(), p);
    }
}

impl fido::Keys for SepData {
    fn key_create(&self) -> Option<(KVec<u8>, [u8; 65])> {
        use sks::DerVal::{Int, Utf8};
        let blob = self.key_op("fido create", sks::der_dict(&[(b"bc", Int(0xb)), (b"kt", Int(4)), (b"o", Utf8(b"oc"))]))?;
        let (_, _, rk) = sks::der_get(&blob, b"rk")?;
        let (t, public, _) = sks::der_get(rk, b"pub")?;
        if t != 0x04 || public.len() != 65 || public[0] != 4 {
            dev_err!(self.dev, "[sep2] fido: a ref key's public half is {} bytes, not X9.63's 65\n", public.len());
            return None;
        }
        let mut p = [0u8; 65];
        p.copy_from_slice(public);
        Some((blob, p))
    }

    fn key_sign(&self, blob: &[u8], digest: &[u8; 32]) -> Option<KVec<u8>> {
        use sks::DerVal::{Octets, Raw, Utf8};
        let out = self.key_op("fido sign", sks::der_dict(&[(b"d", Octets(digest)), (b"o", Utf8(b"osgn")), (b"rk", Raw(blob))]))?;
        let sig = match sks::der_next(&out) {
            Some((0x04, v, _)) => v,
            _ => &out[..],
        };
        let mut v = KVec::new();
        v.extend_from_slice(sig, GFP_KERNEL).ok()?;
        Some(v)
    }

    fn key_ecdh(&self, blob: &[u8], peer: &[u8; 65]) -> Option<[u8; 32]> {
        use sks::DerVal::{Octets, Raw, Utf8};
        let mut out = self.key_op("fido ecdh", sks::der_dict(&[(b"o", Utf8(b"ock")), (b"pub", Octets(peer)), (b"rk", Raw(blob))]))?;
        let r = match sks::der_next(&out) {
            Some((0x04, v, _)) if v.len() == 32 => {
                let mut x = [0u8; 32];
                x.copy_from_slice(v);
                Some(x)
            }
            _ => None,
        };
        out.iter_mut().for_each(|b| *b = 0);
        r
    }

    fn seal(&self, data: &[u8]) -> Option<KVec<u8>> {
        let h = self.fido_handle.load(CR);
        let img = self.key_call("fido seal", sks::CMD_KC_WRAP, sks::kc_wrap(h, 0xb, data))?;
        let (w, _) = sks::parse_kc_wrap(self.reply_body(sks::CMD_KC_WRAP, &img))?;
        let mut v = KVec::new();
        v.extend_from_slice(w, GFP_KERNEL).ok()?;
        Some(v)
    }

    fn unseal(&self, blob: &[u8]) -> Option<KVec<u8>> {
        let h = self.fido_handle.load(CR);
        let mut img = self.key_call("fido unseal", sks::CMD_KC_UNWRAP, sks::kc_unwrap(h, 0xb, blob))?;
        let r = sks::parse_kc_unwrap(self.reply_body(sks::CMD_KC_UNWRAP, &img)).and_then(|(d, _, _)| {
            let mut v = KVec::new();
            v.extend_from_slice(d, GFP_KERNEL).ok()?;
            Some(v)
        });
        img.iter_mut().for_each(|b| *b = 0);
        r
    }

    /// A touch on the Touch ID sensor within 30 s (bio::presence), CTAPHID's keepalive sent while it waits.
    fn presence(&self) -> core::result::Result<(), u8> {
        match bio::presence(self, 30_000, &mut || self.fido_keepalive()) {
            bio::Presence::Touch => Ok(()),
            bio::Presence::Timeout => Err(fido::ERR_USER_ACTION_TIMEOUT),
            bio::Presence::Cancelled => Err(fido::ERR_KEEPALIVE_CANCEL),
            bio::Presence::Failed => Err(fido::ERR_OPERATION_DENIED),
        }
    }

    fn verify(&self) -> core::result::Result<(), u8> {
        match bio::verify(self, 30_000, &mut || self.fido_keepalive()) {
            bio::Verify::Matched => Ok(()),
            bio::Verify::NoMatch => Err(fido::ERR_UV_INVALID),
            bio::Verify::LockedOut => Err(fido::ERR_UV_BLOCKED),
            bio::Verify::Unavailable => Err(fido::ERR_UNSUPPORTED_OPTION),
            bio::Verify::Timeout => Err(fido::ERR_USER_ACTION_TIMEOUT),
            bio::Verify::Cancelled => Err(fido::ERR_KEEPALIVE_CANCEL),
            bio::Verify::Failed => Err(fido::ERR_OPERATION_DENIED),
        }
    }

    fn uv_ready(&self) -> bool {
        bio::verify_ready(self)
    }

    fn random(&self, buf: &mut [u8]) {
        // SAFETY: get_random_bytes writes `len` bytes at `buf`.
        unsafe { bindings::get_random_bytes(buf.as_mut_ptr().cast(), buf.len()) };
    }
}
