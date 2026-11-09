// SPDX-License-Identifier: GPL-2.0-only

//! Stages 15 and 16: Touch ID's interface for userspace, `/dev/apple-sep-bio` (include/uapi/linux/apple-sep-bio.h).
//!
//! After the bring-up (the session unlocked, the sensor calibrated and off), each ioctl runs under
//! `SepData::bio_op`, one at a time, for one opener: the info, a sealed record loaded back (0x6d, 0x71, as
//! biometrickitd's `loadCatacombForComponent:` and `loadBioLockoutRecord`), a user's identities (0x6e, as its
//! `syncTemplateListForUser:`). From stage 16 also an enrolment or a match: begun (the sensor brought up again as
//! after the calibration, the contexts, the credential), one touch per CAPTURE (stage 13's and 14's relays), ended
//! (the sensor off), then saved by userspace in biometrickitd's order (save_order), each catacomb confirmed (0x37)
//! only once userspace says it holds it. CANCEL takes no lock: it sets `SepData::bio_cancel`, which the capture's
//! waits read. At stage 17 the session is not unlocked at the bring-up: UNLOCK gives the identity once a boot and runs
//! stage 7's sequence on it (`SepData::unlock`), handing back the bag the SEP makes when none was given.

use crate::{mesa, proto, Relay, SepData};
use kernel::{
    fs::File,
    ioctl::{_IO, _IOR, _IOW, _IOWR},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    sync::{atomic::Relaxed, Arc, ArcBorrow, CondVarTimeoutResult},
    time,
    uaccess::{UserPtr, UserSlice},
};

const VERSION: u32 = 4;
const STATE_READY: u32 = 1;
const STATE_OPS: u32 = 2;
const STATE_UNLOCKED: u32 = 4;
const STATE_STOPPED: u32 = 8;
const WAIT_MAX_MS: u32 = 120_000;
const KIND_CATACOMB: u32 = 1;
const KIND_LOCKOUT: u32 = 2;
const BLOB_MAX: usize = proto::SAVE_MAX;
const LIST_MAX: usize = 16;
/// The match flags taken (BKOptionMatchForUnlock).
const MATCH_FLAGS: u32 = proto::MATCH_UNLOCK;

const R_NO_FINGER: u32 = 1;
const R_RETRY: u32 = 2;
const R_ENROL_STEP: u32 = 3;
const R_ENROL_DONE: u32 = 4;
const R_MATCHED: u32 = 5;
const R_NO_MATCH: u32 = 6;
const R_CANCELLED: u32 = 7;
const R_FAILED: u32 = 8;
const R_LOCKED_OUT: u32 = 9;

const INFO_LEN: usize = 32;
const BLOB_LEN: usize = 24;
const LIST_HEAD: usize = 16;
const LIST_LEN: usize = LIST_HEAD + LIST_MAX * proto::IDENTITY_LIST_REC;
const BEGIN_LEN: usize = 16;
const CAPTURE_LEN: usize = 48;
const UNLOCK_LEN: usize = 64;
/// The largest wrapped bag: identity_inputs' bound.
const BAG_MAX: usize = crate::sks::BUF_LEN / 2;

const IOC: u32 = 0xB9;
const GET_INFO: u32 = _IOR::<[u8; INFO_LEN]>(IOC, 0x00);
const LOAD: u32 = _IOWR::<[u8; BLOB_LEN]>(IOC, 0x01);
const LIST: u32 = _IOWR::<[u8; LIST_LEN]>(IOC, 0x02);
const ENROL: u32 = _IOW::<[u8; BEGIN_LEN]>(IOC, 0x03);
const MATCH: u32 = _IOW::<[u8; BEGIN_LEN]>(IOC, 0x04);
const CAPTURE: u32 = _IOWR::<[u8; CAPTURE_LEN]>(IOC, 0x05);
const END: u32 = _IO(IOC, 0x06);
const SAVE_NEXT: u32 = _IOWR::<[u8; BLOB_LEN]>(IOC, 0x07);
const SAVE_CONFIRM: u32 = _IO(IOC, 0x08);
const CANCEL: u32 = _IO(IOC, 0x09);
const UNLOCK: u32 = _IOWR::<[u8; UNLOCK_LEN]>(IOC, 0x0a);
const DELETE: u32 = _IOW::<[u8; DELETE_LEN]>(IOC, 0x0c);
const DELETE_LEN: usize = proto::REMOVE_TEMPLATE_LEN;
const WAIT: u32 = _IOW::<[u8; 4]>(IOC, 0x0b);

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from(le32(b, at)) | u64::from(le32(b, at + 4)) << 32
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Enrol,
    Match,
}

/// An enrolment or a match, from its ioctl to its END.
struct Op {
    kind: Kind,
    uid: u32,
    flags: u32,
    /// An enrolment's credential, its ACM context (cred_open), open until the save ends. A match opens none, as
    /// macOS's (biometrickitd `performMatchCommand:` 0x100015ae8, the kext's `commandStartMatch` 0xfffffe0009ab7920):
    /// the secret's check is what clears the SEP's failed-match count, so a credential per match never let it lock out.
    acm: Option<[u8; proto::ACM_HANDLE_LEN]>,
    touches: u32,
    /// The last touch's image was relayed: the next capture first waits for the finger to lift (SepData::wait_lift).
    lift: bool,
    /// A result ended it: END is all that is left.
    ended: bool,
    /// The enrolment is complete (0x08's done flag): END saves it instead of cancelling it.
    complete: bool,
}

/// The save END leaves (the catacombs in save_order, then the lockout record; the credential closes after it) or
/// DELETE leaves (the catacombs only, no credential).
struct Save {
    uid: u32,
    acm: Option<[u8; proto::ACM_HANDLE_LEN]>,
    /// The lockout record ends the save; without it, the last catacomb's confirm does.
    lockout: bool,
    order: KVec<i32>,
    next: usize,
    /// What SAVE_NEXT handed out and SAVE_CONFIRM has not confirmed: its kind and component.
    handed: Option<(u32, i32)>,
}

/// What `SepData::bio_op` guards.
#[derive(Default)]
pub(crate) struct OpState {
    open: bool,
    op: Option<Op>,
    save: Option<Save>,
    /// The components whose last load was refused (load_refused): one more load of each goes through though the
    /// SEP then shows it active. macOS drops the file instead; Aurora's driver resends the blob once after 0x8002
    /// when the user shows no identity. For the first enrolment with a finger, to tell the two apart.
    refused: KVec<i32>,
}

/// The misc device and the driver data it serves; held by `SepData::service` until remove() breaks the cycle.
#[pin_data]
pub(crate) struct Service {
    data: Arc<SepData>,
    #[pin]
    misc: MiscDeviceRegistration<Bio>,
}

impl Service {
    pub(crate) fn new(data: Arc<SepData>) -> Result<Pin<KBox<Service>>> {
        KBox::pin_init(
            try_pin_init!(Service {
                data,
                misc <- MiscDeviceRegistration::register(MiscDeviceOptions { name: c"apple-sep-bio" }),
            }),
            GFP_KERNEL,
        )
    }
}

pub(crate) struct Bio;

#[vtable]
impl MiscDevice for Bio {
    type Ptr = Arc<SepData>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Arc<SepData>> {
        // SAFETY: a registration of Bio is only ever made as the `misc` field of a pinned Service (Service::new),
        // which outlives it: the device is deregistered by the Service's drop.
        let svc = unsafe { &*kernel::container_of!(core::ptr::from_ref(misc).cast_mut(), Service, misc) };
        let mut st = svc.data.bio_op.lock();
        if st.open {
            return Err(EBUSY);
        }
        st.open = true;
        drop(st);
        Ok(svc.data.clone())
    }

    fn release(data: Arc<SepData>, _file: &File) {
        let mut st = data.bio_op.lock();
        abandon(&data, &mut st);
        st.open = false;
    }

    fn ioctl(data: ArcBorrow<'_, SepData>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        let user = UserPtr::from_addr(arg);
        match cmd {
            GET_INFO => info(&data, user),
            LOAD => load(&data, user),
            LIST => list(&data, user),
            ENROL => begin(&data, user, Kind::Enrol),
            MATCH => begin(&data, user, Kind::Match),
            CAPTURE => capture(&data, user),
            END => end(&data),
            SAVE_NEXT => save_next(&data, user),
            SAVE_CONFIRM => save_confirm(&data),
            UNLOCK => unlock(&data, user),
            WAIT => wait(&data, user),
            DELETE => delete(&data, user),
            CANCEL => {
                data.bio_cancel.store(true, Relaxed);
                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }
}

/// The driver is up for operations: the bring-up done and not going away.
fn ready(data: &SepData) -> bool {
    data.bio_ready.load(Relaxed) && !data.closing.load(Relaxed)
}

/// Enrolments, matches and saves are open (stage 16).
fn ops_open(data: &SepData) -> bool {
    data.stage >= 16 && ready(data)
}

/// The bring-up stopped short of the service, or the driver is going away: no operation runs.
fn stopped(data: &SepData) -> bool {
    data.bio_stopped.load(Relaxed) || data.closing.load(Relaxed)
}

/// WAIT: {u32 timeout_ms}, until the bring-up has ended: 0 ready, ENODEV stopped, ETIMEDOUT. The node is there from
/// probe; the flags are set under `state`'s lock (SepData::bio_settle), held here from the check until the sleep.
fn wait(data: &SepData, user: UserPtr) -> Result<isize> {
    let mut b = [0u8; 4];
    UserSlice::new(user, 4).reader().read_slice(&mut b)?;
    let ms = le32(&b, 0);
    if ms == 0 || ms > WAIT_MAX_MS {
        return Err(EINVAL);
    }
    let mut remaining = time::msecs_to_jiffies(ms);
    let mut st = data.state.lock();
    loop {
        if ready(data) {
            return Ok(0);
        }
        if stopped(data) {
            return Err(ENODEV);
        }
        if remaining == 0 {
            return Err(ETIMEDOUT);
        }
        remaining = match data.wq.wait_interruptible_timeout(&mut st, remaining) {
            CondVarTimeoutResult::Woken { jiffies } => jiffies,
            CondVarTimeoutResult::Signal { .. } => return Err(ERESTARTSYS),
            CondVarTimeoutResult::Timeout => 0,
        };
    }
}

fn info(data: &SepData, user: UserPtr) -> Result<isize> {
    let mut b = [0u8; INFO_LEN];
    put32(&mut b, 0, VERSION);
    let state = (if ready(data) { STATE_READY } else { 0 })
        | (if ops_open(data) { STATE_OPS } else { 0 })
        | (if data.identity.as_ref().is_some() { STATE_UNLOCKED } else { 0 })
        | (if stopped(data) { STATE_STOPPED } else { 0 });
    put32(&mut b, 4, state);
    put32(&mut b, 8, u32::from(mesa::SENSOR_ID));
    UserSlice::new(user, INFO_LEN).writer().write_slice(&b)?;
    Ok(0)
}

fn load(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, BLOB_LEN).reader_writer();
    let mut b = [0u8; BLOB_LEN];
    r.read_slice(&mut b)?;
    let (kind, who, len) = (le32(&b, 0), le32(&b, 4) as i32, le32(&b, 8) as usize);
    if len == 0 || len > BLOB_MAX || (kind == KIND_CATACOMB && len <= proto::CATACOMB_HEADER) {
        return Err(EINVAL);
    }
    let mut rec = KVVec::new();
    UserSlice::new(UserPtr::from_addr(le64(&b, 16) as usize), len).read_all(&mut rec, GFP_KERNEL)?;
    let mut st = data.bio_op.lock();
    if !ready(data) {
        return Err(EAGAIN);
    }
    if st.op.is_some() || st.save.is_some() {
        return Err(EBUSY);
    }
    let status = match kind {
        // the header names its component at 8, as 0x6c's check and the lab's saved records
        KIND_CATACOMB if le32(&rec, 8) as i32 == who => {
            // only a component the SEP does not show active, as loadCatacombForComponent: does
            let states = data.components("before a load").ok_or(EIO)?;
            let again = st.refused.iter().position(|&w| w == who);
            if again.is_none() && states.iter().any(|&(w, s)| w == who && s & proto::COMPONENT_ACTIVE != 0) {
                return Err(EALREADY);
            }
            if let Some(i) = again {
                st.refused.swap_remove(i);
                vinfo!(data.dev, "[sep2] bio: component {}'s catacomb again, once, after its refusal\n", who);
            }
            let a = data.sbio_transact(proto::SBIO_LOAD_CATACOMB, &rec, true, 0).ok_or(EIO)?;
            if proto::load_refused(a.status) {
                dev_err!(data.dev, "[sep2] bio: component {}'s catacomb refused as corrupted ({:#x})\n", who, a.status);
                if again.is_none() {
                    st.refused.push(who, GFP_KERNEL)?;
                }
            }
            a.status
        }
        // builds 30-32 of the lab: 0xffffffff after the user's catacomb took; not an error here
        KIND_LOCKOUT => data.sbio_transact(proto::SBIO_LOAD_LOCKOUT, &rec, true, 0).ok_or(EIO)?.status,
        _ => return Err(EINVAL),
    };
    drop(st);
    let what = if kind == KIND_CATACOMB { "catacomb" } else { "lockout record" };
    vinfo!(data.dev, "[sep2] bio: loaded a {} ({:#x} bytes): status {:#x}\n", what, len, status);
    put32(&mut b, 12, status);
    w.write_slice(&b)?;
    Ok(0)
}

fn list(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, LIST_LEN).reader_writer();
    let mut head = [0u8; LIST_HEAD];
    r.read_slice(&mut head)?;
    let uid = le32(&head, 0);
    let a = {
        let _st = data.bio_op.lock();
        if !ready(data) {
            return Err(EAGAIN);
        }
        data.sbio_query(proto::SBIO_IDENTITIES_LIST, &uid.to_le_bytes(), false).ok_or(EIO)?
    };
    let mut out = KVVec::new();
    out.extend_from_slice(&[0u8; LIST_LEN], GFP_KERNEL)?;
    put32(&mut out, 0, uid);
    put32(&mut out, 4, a.status);
    if a.status == 0 {
        if a.data.len() % proto::IDENTITY_LIST_REC != 0 {
            dev_err!(data.dev, "[sep2] bio: 0x6e's answer is {:#x} bytes, not whole records\n", a.data.len());
            return Err(EIO);
        }
        let n = a.data.len() / proto::IDENTITY_LIST_REC;
        put32(&mut out, 8, n as u32);
        let shown = n.min(LIST_MAX) * proto::IDENTITY_LIST_REC;
        out[LIST_HEAD..LIST_HEAD + shown].copy_from_slice(&a.data[..shown]);
        vinfo!(data.dev, "[sep2] bio: uid {} has {} identities\n", uid, n);
    }
    w.write_slice(&out)?;
    Ok(0)
}

/// UNLOCK (stage 17): {u32 uid, u32 bag_len, the UUID (16), the secret (32), u64 bag}, once a boot. A bag_len of 0
/// asks the SEP to make the bag (identity_create), written back to `bag`, a BAG_MAX buffer, with its length in
/// bag_len; otherwise the kept bag of bag_len bytes is loaded. The identity is checked as identity_inputs checks the
/// identity file; the secret is not logged, and the copy on the stack is cleared.
fn unlock(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, UNLOCK_LEN).reader_writer();
    let mut b = [0u8; UNLOCK_LEN];
    r.read_slice(&mut b)?;
    let (uid, bag_len, bag_ptr) = (le32(&b, 0), le32(&b, 4) as usize, le64(&b, 56) as usize);
    let mut id = crate::Identity { uuid: [0; 16], secret: [0; 32], uid, bag: None };
    id.uuid.copy_from_slice(&b[8..24]);
    id.secret.copy_from_slice(&b[24..56]);
    b[24..56].fill(0);
    if uid < 10 || uid > i32::MAX as u32 || id.uuid == [0; 16] || id.secret == [0; 32] || bag_len > BAG_MAX {
        id.secret.fill(0);
        return Err(EINVAL);
    }
    if bag_len > 0 {
        let mut v = KVec::new();
        UserSlice::new(UserPtr::from_addr(bag_ptr), bag_len).read_all(&mut v, GFP_KERNEL)?;
        id.bag = Some(v);
    }
    let st = data.bio_op.lock();
    if data.stage < 17 {
        return Err(ENOTTY);
    }
    if !ready(data) {
        return Err(EAGAIN);
    }
    if st.op.is_some() || st.save.is_some() {
        return Err(EBUSY);
    }
    if data.identity.as_ref().is_some() {
        return Err(EALREADY);
    }
    let made = data.unlock(id).map_err(|why| {
        dev_err!(data.dev, "[sep2] bio: UNLOCK for uid {}: {}\n", uid, why);
        EIO
    })?;
    drop(st);
    match made {
        Some(bag) => {
            UserSlice::new(UserPtr::from_addr(bag_ptr), bag.len()).writer().write_slice(&bag)?;
            put32(&mut b, 4, bag.len() as u32);
            vinfo!(data.dev, "[sep2] bio: uid {}'s session unlocked; a new bag of {:#x} bytes handed back\n", uid, bag.len());
        }
        None => vinfo!(data.dev, "[sep2] bio: uid {}'s session unlocked with the kept bag\n", uid),
    }
    w.write_slice(&b[..8])?;
    Ok(0)
}

/// ENROL and MATCH, for the identity file's user only (the credential is its session's): the sensor brought up again
/// as resetSensorAndLoadPatch runs it after the calibration (mesa_pass), then for an enrolment its contexts
/// (enrol_contexts), the credential (cred_open) and BEGIN_ENROL; for a match the user's component active (0x6b) and no
/// credential, as macOS opens none for a match. The capture's frames armed for the touches.
fn begin(data: &SepData, user: UserPtr, kind: Kind) -> Result<isize> {
    let mut b = [0u8; BEGIN_LEN];
    UserSlice::new(user, BEGIN_LEN).reader().read_slice(&mut b)?;
    let (uid, flags) = (le32(&b, 0), le32(&b, 4));
    let allowed = if kind == Kind::Match { MATCH_FLAGS } else { 0 };
    if flags & !allowed != 0 || data.identity.as_ref().is_none_or(|id| id.uid != uid) {
        return Err(EINVAL);
    }
    let mut st = data.bio_op.lock();
    if !ops_open(data) {
        return Err(EAGAIN);
    }
    if st.op.is_some() || st.save.is_some() {
        return Err(EBUSY);
    }
    if kind == Kind::Match && locked_out(data, uid) {
        return Err(EPERM);
    }
    data.bio_cancel.store(false, Relaxed);
    data.capture_armed.store(false, Relaxed);
    if !data.mesa_pass(true) {
        return Err(EIO);
    }
    let how = if kind == Kind::Enrol { "an enrolment" } else { "a match" };
    let acm = match prepare(data, kind, uid) {
        Ok(acm) => acm,
        Err((e, why)) => {
            let _ = mesa::capture_arm(false);
            let _ = mesa::power(false);
            dev_err!(data.dev, "[sep2] bio: {} for uid {} not begun: {}\n", how, uid, why);
            return Err(e);
        }
    };
    st.op = Some(Op { kind, uid, flags, acm, touches: 0, lift: false, ended: false, complete: false });
    dev_info!(data.dev, "[sep2] bio: {} for uid {} begun\n", how, uid);
    Ok(0)
}

/// begin's SEP side, after the sensor's bring-up: an enrolment's open credential (none for a match), or the errno and
/// why not, with the credential closed again.
fn prepare(data: &SepData, kind: Kind, uid: u32) -> core::result::Result<Option<[u8; proto::ACM_HANDLE_LEN]>, (Error, &'static str)> {
    match kind {
        Kind::Enrol => data.enrol_contexts(uid, false).map_err(|why| (EIO, why))?,
        Kind::Match => {
            let states = data.components("before a match").ok_or((EIO, "0x6b was not answered status 0"))?;
            if !states.iter().any(|&(w, st)| w == uid as i32 && st & proto::COMPONENT_ACTIVE != 0) {
                return Err((ENOENT, "the user's component is not loaded"));
            }
            mesa::capture_arm(true).map_err(|_| (EIO, "the capture's frames could not be armed"))?;
            return Ok(None);
        }
    }
    let acm = data.cred_open().map_err(|why| (EACCES, why))?;
    let armed = mesa::capture_arm(true).is_ok();
    let begun = armed && data.enrol_sbio(proto::SBIO_BEGIN_ENROL, &proto::begin_enrol(uid, &acm), true).is_some();
    if !begun {
        data.cred_close(&acm, uid);
        return Err((EIO, if armed { "BEGIN_ENROL was not answered status 0" } else { "the capture's frames could not be armed" }));
    }
    Ok(Some(acm))
}

/// A capture's outcome, as apple_sep_bio_capture gives it.
#[derive(Default)]
struct Outcome {
    result: u32,
    progress: u32,
    feedback: u32,
    status: u32,
    uid: u32,
    uuid: [u8; 16],
}

/// CAPTURE: one touch for the open operation, blocking up to its window for the finger.
fn capture(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, CAPTURE_LEN).reader_writer();
    let mut b = [0u8; CAPTURE_LEN];
    r.read_slice(&mut b)?;
    let window = le32(&b, 0);
    if window == 0 || window > crate::CAPTURE_MS {
        return Err(EINVAL);
    }
    let o = {
        let mut st = data.bio_op.lock();
        if !ops_open(data) {
            return Err(EAGAIN);
        }
        match st.op.as_mut() {
            Some(op) if !op.ended => touch(data, op, window)?,
            _ => return Err(EINVAL),
        }
    };
    for (at, v) in [(4, o.result), (8, o.progress), (12, o.feedback), (16, o.status), (20, o.uid)] {
        put32(&mut b, at, v);
    }
    b[24..40].copy_from_slice(&o.uuid);
    w.write_slice(&b)?;
    Ok(0)
}

/// One touch: a match refused while the SEP reports the user locked out; the lift after the last image
/// (SepData::wait_lift); the capture (capture_image); the image relayed as stage 13 (enrol_relay) or stage 14
/// (match_relay) relay it, and zeroed.
fn touch(data: &SepData, op: &mut Op, window: u32) -> Result<Outcome> {
    let mut o = Outcome::default();
    if op.kind == Kind::Match && locked_out(data, op.uid) {
        op.ended = true;
        o.result = R_LOCKED_OUT;
        return Ok(o);
    }
    if core::mem::take(&mut op.lift) {
        match data.wait_lift(window) {
            Ok(()) => {}
            Err(crate::CAPTURE_CANCELLED) => {
                op.ended = true;
                o.result = R_CANCELLED;
                return Ok(o);
            }
            Err(crate::CAPTURE_NO_IMAGE) => {
                // the finger stayed the whole window: no new touch; the next CAPTURE waits for the lift again
                op.lift = true;
                o.result = R_NO_FINGER;
                return Ok(o);
            }
            Err(why) => {
                op.ended = true;
                dev_err!(data.dev, "[sep2] bio: the lift failed: {}\n", why);
                return Err(EIO);
            }
        }
    }
    if data.bio_cancel.load(Relaxed) {
        op.ended = true;
        o.result = R_CANCELLED;
        return Ok(o);
    }
    let (mut img, n, at) = match data.capture_image(window) {
        Ok(v) => v,
        Err(why) => {
            // the sensor stays armed for the next window (capture_image); the end idles it (stop)
            match why {
                crate::CAPTURE_NO_IMAGE => o.result = R_NO_FINGER,
                crate::CAPTURE_CANCELLED => {
                    op.ended = true;
                    o.result = R_CANCELLED;
                }
                _ => {
                    op.ended = true;
                    dev_err!(data.dev, "[sep2] bio: the capture failed: {}\n", why);
                    return Err(EIO);
                }
            }
            return Ok(o);
        }
    };
    let ticks = mesa::ticks();
    let i = op.touches;
    op.touches += 1;
    data.image_check_log(&img, n, at, i == 0);
    match op.kind {
        Kind::Enrol => match data.enrol_relay(i, &img, ticks) {
            Relay::Next(took, progress, feedback) => {
                o.result = if took { R_ENROL_STEP } else { R_RETRY };
                o.progress = progress.into();
                o.feedback = feedback;
            }
            Relay::Done(crate::ENROL_COMPLETE) => {
                op.complete = true;
                op.ended = true;
                o.result = R_ENROL_DONE;
            }
            Relay::Done(why) => {
                op.ended = true;
                o.result = R_FAILED;
                dev_err!(data.dev, "[sep2] bio: the enrolment failed: {}\n", why);
            }
        },
        Kind::Match => op.ended = match_relay(data, op, i, &img, ticks, &mut o),
    }
    img.fill(0);
    drop(img);
    if !op.ended {
        op.lift = true;
    } else if op.kind == Kind::Match && o.result != R_MATCHED && locked_out(data, op.uid) {
        o.result = R_LOCKED_OUT;
    }
    Ok(o)
}

/// The SEP reports the user's matches locked out (its request 1: BioLockout after its failed-match limit, or
/// PasscodeLockout): as the kext's checkAutoMatchLockoutConditions, no image of theirs goes to a match.
fn locked_out(data: &SepData, uid: u32) -> bool {
    match data.lock_state(uid) {
        Some(l) if l & (proto::LOCK_BIO | proto::LOCK_PASSCODE) != 0 => {
            dev_err!(data.dev, "[sep2] bio: uid {}'s matches are locked out (the SEP's lock state {:#x})\n", uid, l);
            true
        }
        _ => false,
    }
}

/// A match's image as stage 14's run_match relays it: 0x23, 0x06 with the match's flags and user, 0x65, 0x07; 0x09
/// for an image usable for a match; 0x22 after. Whether the result ends the match.
fn match_relay(data: &SepData, op: &Op, i: u32, img: &[u8], ticks: u64, o: &mut Outcome) -> bool {
    let init = proto::image_init_match(0, ticks, op.flags, op.uid);
    let a = match data.relay_head(img, &init) {
        Ok(a) => a,
        Err(why) => {
            dev_err!(data.dev, "[sep2] bio: the match's image {} failed: {}\n", i, why);
            o.result = R_FAILED;
            return true;
        }
    };
    vinfo!(data.dev, "[sep2] bio: match image {}: error {}, for a match {}, assessment {}, feedback {}\n", i, a.err, a.for_match, a.assessment, a.feedback);
    let mut ended = false;
    if a.for_match == 0 {
        o.result = R_RETRY;
        o.feedback = a.feedback;
    } else {
        match data.sbio_query(proto::SBIO_MATCH_RESULT, &[], false) {
            Some(r) if r.status == 0 => match proto::parse_match(&r.data) {
                Some(m) if m.user == u32::MAX => o.result = R_NO_MATCH,
                Some(m) => {
                    vinfo!(data.dev, "[sep2] bio: match image {}: 0x09 names user {}\n", i, m.user as i32);
                    o.result = R_MATCHED;
                    o.uid = m.user;
                    o.uuid = m.uuid;
                    ended = true;
                }
                None => {
                    dev_err!(data.dev, "[sep2] bio: 0x09's reply is {:#x} bytes, not 0xca2\n", r.data.len());
                    o.result = R_FAILED;
                    ended = true;
                }
            },
            Some(r) => {
                if r.status == proto::MATCH_STATUS_END {
                    dev_err!(data.dev, "[sep2] bio: match image {}: 0x09 answered 0x56, which ends a match\n", i);
                }
                o.result = R_FAILED;
                o.status = r.status;
                ended = true;
            }
            None => {
                o.result = R_FAILED;
                ended = true;
            }
        }
    }
    if a.for_match != 0 {
        // the match policy again after each 0x09, as handleMatch reads it (0xfffffe0009acb664); logged
        let _ = data.sbio_query(proto::SBIO_MATCH_POLICY, &[], true);
    }
    if data.enrol_sbio(proto::SBIO_BG_OPS, &[], false).is_none() && !ended {
        o.result = R_FAILED;
        ended = true;
    }
    ended
}

/// The touches' end: an incomplete enrolment cancelled (0x05, commandCancel in mode 3), the sensor idle, its capture
/// frames disarmed and its power off. Only the sensor once the driver is going away.
fn stop(data: &SepData, op: &Op) {
    if op.kind == Kind::Enrol && !op.complete && ready(data) {
        let cancelled = data.enrol_sbio(proto::SBIO_CANCEL, &[], true).is_some();
        vinfo!(data.dev, "[sep2] bio: the enrolment {}\n", if cancelled { "cancelled" } else { "NOT cancelled (0x05)" });
    }
    // a match's end, as macOS's commandCancel in match mode and checkMatchStop send it (AppleMesaSEPDriver_272
    // 0xfffffe0009ada3b4): 0x0B with no data
    if op.kind == Kind::Match && ready(data) {
        let ended = data.enrol_sbio(proto::SBIO_MATCH_END, &[], false).is_some();
        vinfo!(data.dev, "[sep2] bio: the match {}\n", if ended { "ended (0x0b)" } else { "NOT ended (0x0b)" });
    }
    data.sensor_idle("the operation's end");
    let _ = mesa::capture_arm(false);
    let off = mesa::power(false).is_ok();
    vinfo!(data.dev, "[sep2] bio: {} touches; the sensor {}\n", op.touches, if off { "off" } else { "NOT switched off" });
}

/// END: the touches stopped (stop), then the save opened in biometrickitd's order (save_order) with the lockout record
/// last; the credential stays open for it.
fn end(data: &SepData) -> Result<isize> {
    let mut st = data.bio_op.lock();
    let op = st.op.take().ok_or(EINVAL)?;
    data.bio_cancel.store(false, Relaxed);
    stop(data, &op);
    if !ready(data) {
        return Err(EAGAIN);
    }
    if op.complete {
        data.identities("after the enrolment");
    }
    let order = data.components("before the save").map(|c| crate::save_order(&c));
    match order {
        Some(Ok(order)) => {
            vinfo!(data.dev, "[sep2] bio: the save: {} catacombs, then the lockout record\n", order.len());
            st.save = Some(Save { uid: op.uid, acm: op.acm, lockout: true, order, next: 0, handed: None });
            Ok(0)
        }
        Some(Err(e)) => {
            if let Some(acm) = op.acm {
                data.cred_close(&acm, op.uid);
            }
            Err(e)
        }
        None => {
            if let Some(acm) = op.acm {
                data.cred_close(&acm, op.uid);
            }
            Err(EIO)
        }
    }
}

/// SAVE_NEXT: the next record of the save, prepared by the SEP (0x6c for a catacomb, its user at 8 checked; 0x70 for
/// the lockout record) and copied out; again until SAVE_CONFIRM. A second 0x6c for an unconfirmed catacomb is not
/// verified.
fn save_next(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, BLOB_LEN).reader_writer();
    let mut b = [0u8; BLOB_LEN];
    r.read_slice(&mut b)?;
    let (room, ptr) = (le32(&b, 8) as usize, le64(&b, 16));
    let mut st = data.bio_op.lock();
    if !ops_open(data) {
        return Err(EAGAIN);
    }
    let s = st.save.as_mut().ok_or(ENODATA)?;
    let (kind, who, rec) = match s.order.get(s.next) {
        Some(&who) => {
            let a = data.sbio_transact(proto::SBIO_SAVE_PREPARE, &proto::save_selector(who), false, proto::SAVE_MAX).ok_or(EIO)?;
            let named = a.data.get(8..12).map(|n| le32(n, 0) as i32);
            if a.status != 0 || a.data.len() <= proto::CATACOMB_HEADER || named != Some(who) {
                dev_err!(data.dev, "[sep2] bio: 0x6c for component {}: status {:#x}, {:#x} bytes naming {:?}\n", who, a.status, a.data.len(), named);
                return Err(EIO);
            }
            (KIND_CATACOMB, who, a.data)
        }
        None if !s.lockout => return Err(ENODATA),
        None => {
            let a = data.sbio_transact(proto::SBIO_LOCKOUT_SAVE, &[], false, proto::SAVE_MAX).ok_or(EIO)?;
            if a.status != 0 || a.data.is_empty() {
                dev_err!(data.dev, "[sep2] bio: 0x70: status {:#x}, {:#x} bytes\n", a.status, a.data.len());
                return Err(EIO);
            }
            (KIND_LOCKOUT, 0, a.data)
        }
    };
    put32(&mut b, 0, kind);
    put32(&mut b, 4, who as u32);
    put32(&mut b, 8, rec.len() as u32);
    put32(&mut b, 12, 0);
    if rec.len() > room {
        w.write_slice(&b)?;
        return Err(ENOSPC);
    }
    UserSlice::new(UserPtr::from_addr(ptr as usize), rec.len()).writer().write_slice(&rec)?;
    w.write_slice(&b)?;
    s.handed = Some((kind, who));
    let what = if kind == KIND_CATACOMB { "a catacomb" } else { "the lockout record" };
    vinfo!(data.dev, "[sep2] bio: the save: {} (component {}), {:#x} bytes, handed out\n", what, who, rec.len());
    Ok(0)
}

/// SAVE_CONFIRM: userspace holds the record SAVE_NEXT handed out. A catacomb is confirmed to the SEP (0x37, as the kext's
/// 0x3F); the lockout record has no confirm and ends the save, the credential closed.
fn save_confirm(data: &SepData) -> Result<isize> {
    let mut st = data.bio_op.lock();
    if !ops_open(data) {
        return Err(EAGAIN);
    }
    let s = st.save.as_mut().ok_or(EINVAL)?;
    match s.handed.ok_or(EINVAL)? {
        (KIND_CATACOMB, who) => {
            data.enrol_sbio(proto::SBIO_SAVE_CONFIRM, &proto::save_selector(who), true).ok_or(EIO)?;
            s.handed = None;
            s.next += 1;
            vinfo!(data.dev, "[sep2] bio: the save: component {} confirmed (0x37)\n", who);
            if !s.lockout && s.next >= s.order.len() {
                st.save = None;
                vinfo!(data.dev, "[sep2] bio: the save done\n");
            }
        }
        _ => {
            if let Some(s) = st.save.take() {
                if let Some(acm) = s.acm {
                    data.cred_close(&acm, s.uid);
                }
            }
            vinfo!(data.dev, "[sep2] bio: the save done\n");
        }
    }
    Ok(0)
}

/// DELETE (stage 17): {u32 uid, the identity's UUID}, the session user's identity removed (0x57, RemoveTemplate, no
/// credential), then a save of the save-pending catacombs without the lockout record, as biometrickitd's
/// removeIdentity saves (saveCatacomb; touchid-lift.md §2): SAVE_NEXT and SAVE_CONFIRM as after END, until ENODATA.
/// ENOENT when the SEP refuses the removal (the status logged).
fn delete(data: &SepData, user: UserPtr) -> Result<isize> {
    let mut b = [0u8; DELETE_LEN];
    UserSlice::new(user, DELETE_LEN).reader().read_slice(&mut b)?;
    let uid = le32(&b, 0);
    if data.identity.as_ref().is_none_or(|id| id.uid != uid) || b[4..] == [0u8; 16] {
        return Err(EINVAL);
    }
    let mut st = data.bio_op.lock();
    if data.stage < 17 {
        return Err(ENOTTY);
    }
    if !ops_open(data) {
        return Err(EAGAIN);
    }
    if st.op.is_some() || st.save.is_some() {
        return Err(EBUSY);
    }
    let a = data.sbio_query(proto::SBIO_REMOVE_TEMPLATE, &b, true).ok_or(EIO)?;
    if a.status != 0 {
        dev_err!(data.dev, "[sep2] bio: 0x57 for one of uid {}'s identities: status {:#x}\n", uid, a.status);
        return Err(ENOENT);
    }
    data.identities("after the delete");
    let order = data.components("after the delete").map(|c| crate::save_order(&c));
    match order {
        Some(Ok(order)) => {
            vinfo!(data.dev, "[sep2] bio: an identity of uid {} removed; the save: {} catacombs\n", uid, order.len());
            if !order.is_empty() {
                st.save = Some(Save { uid, acm: None, lockout: false, order, next: 0, handed: None });
            }
            Ok(0)
        }
        Some(Err(e)) => Err(e),
        None => Err(EIO),
    }
}

/// What a closed file leaves: an open operation stopped as END stops it, a save dropped (what it did not confirm stays
/// save-pending in the SEP, for the next save), the credential closed. Nothing goes to the SEP once the driver is
/// going away.
fn abandon(data: &SepData, st: &mut OpState) {
    let mut cred = None;
    if let Some(op) = st.op.take() {
        stop(data, &op);
        cred = op.acm.map(|acm| (acm, op.uid));
    }
    if let Some(s) = st.save.take() {
        if let Some(acm) = s.acm {
            cred = Some((acm, s.uid));
        }
    }
    if let (Some((acm, uid)), true) = (cred, ready(data)) {
        data.cred_close(&acm, uid);
        vinfo!(data.dev, "[sep2] bio: closed with an operation or a save open: dropped\n");
    }
    data.bio_cancel.store(false, Relaxed);
}
