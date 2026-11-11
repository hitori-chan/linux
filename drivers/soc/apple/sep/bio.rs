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

const VERSION: u32 = 7;
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
const R_TOUCH: u32 = 10;

const INFO_LEN: usize = 32;
const BLOB_LEN: usize = 24;
const LIST_HEAD: usize = 16;
const LIST_LEN: usize = LIST_HEAD + LIST_MAX * proto::IDENTITY_LIST_REC;
const BEGIN_LEN: usize = 16;
const CAPTURE_LEN: usize = 48;
const UNLOCK_LEN: usize = 64;
const SECRET_LEN: usize = 80;
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
const REARM: u32 = _IOW::<[u8; 4]>(IOC, 0x0d);
const PRESENCE: u32 = _IOWR::<[u8; CAPTURE_LEN]>(IOC, 0x0e);
const CHANGE_SECRET: u32 = _IOWR::<[u8; SECRET_LEN]>(IOC, 0x0f);

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

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
            REARM => rearm(&data, user),
            PRESENCE => presence_op(&data, user),
            CHANGE_SECRET => change_secret(&data, user),
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

/// CHANGE_SECRET (interface 7): {u32 uid, u32 bag_len, the old secret (32), the new (32), u64 bag}, UNLOCK's user: the
/// session's secret replaced (SepData::change_secret), the rewrapped bag written to `bag`, a BAG_MAX buffer, its
/// length in bag_len. Neither secret is logged; the copies on the stack are cleared.
fn change_secret(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, SECRET_LEN).reader_writer();
    let mut b = [0u8; SECRET_LEN];
    r.read_slice(&mut b)?;
    let (uid, bag_ptr) = (le32(&b, 0), le64(&b, 72) as usize);
    let (mut old, mut new) = ([0u8; 32], [0u8; 32]);
    old.copy_from_slice(&b[8..40]);
    new.copy_from_slice(&b[40..72]);
    b[8..72].fill(0);
    let changed = (|| {
        if new == [0; 32] || new == old {
            return Err(EINVAL);
        }
        let st = data.bio_op.lock();
        if data.identity.as_ref().map(|id| id.uid) != Some(uid) {
            return Err(EINVAL);
        }
        if st.op.is_some() || st.save.is_some() {
            return Err(EBUSY);
        }
        data.change_secret(&old, &new).map_err(|e| match e {
            crate::SecretError::NoSession => EINVAL,
            crate::SecretError::Wrong => EPERM,
            crate::SecretError::Refused => EIO,
            crate::SecretError::Partial => ENODATA,
        })
    })();
    old.fill(0);
    new.fill(0);
    let bag = changed?;
    if bag.len() > BAG_MAX {
        dev_err!(data.dev, "[sep2] bio: CHANGE_SECRET's bag, {:#x} bytes, is over BAG_MAX\n", bag.len());
        return Err(EOVERFLOW);
    }
    UserSlice::new(UserPtr::from_addr(bag_ptr), bag.len()).writer().write_slice(&bag)?;
    put32(&mut b, 4, bag.len() as u32);
    w.write_slice(&b[..8])?;
    Ok(0)
}

/// PRESENCE: capture's struct, timeout_ms in, result out: one touch and its lift (presence), the image zeroed and
/// never sent to the SEP; CANCEL stops it.
fn presence_op(data: &SepData, user: UserPtr) -> Result<isize> {
    let (mut r, mut w) = UserSlice::new(user, CAPTURE_LEN).reader_writer();
    let mut b = [0u8; CAPTURE_LEN];
    r.read_slice(&mut b)?;
    let window = le32(&b, 0);
    if window == 0 || window > crate::CAPTURE_MS {
        return Err(EINVAL);
    }
    {
        let st = data.bio_op.lock();
        if !ops_open(data) {
            return Err(EAGAIN);
        }
        if st.op.is_some() || st.save.is_some() {
            return Err(EBUSY);
        }
    }
    let result = match presence(data, window, &mut || !data.bio_cancel.load(Relaxed)) {
        Presence::Touch => R_TOUCH,
        Presence::Timeout => R_NO_FINGER,
        Presence::Cancelled => R_CANCELLED,
        Presence::Failed => R_FAILED,
    };
    b[4..].fill(0);
    put32(&mut b, 4, result);
    w.write_slice(&b)?;
    Ok(0)
}

/// REARM: {u32 uid}, UNLOCK's user, once the host accepted the user's password: the session's unlock sent again
/// (SepData::rearm), as macOS's lock screen sends it, which clears the SEP's lockout of the user's matches; then a
/// save of the lockout record alone is open.
fn rearm(data: &SepData, user: UserPtr) -> Result<isize> {
    let mut b = [0u8; 4];
    UserSlice::new(user, 4).reader().read_slice(&mut b)?;
    let uid = le32(&b, 0);
    let mut st = data.bio_op.lock();
    if data.identity.as_ref().map(|id| id.uid) != Some(uid) {
        return Err(EINVAL);
    }
    if st.op.is_some() || st.save.is_some() {
        return Err(EBUSY);
    }
    data.rearm().map_err(|why| {
        dev_err!(data.dev, "[sep2] bio: REARM for uid {}: {}\n", uid, why);
        EIO
    })?;
    // the lockout record as the SEP now holds it, for userspace to keep (SAVE_NEXT, SAVE_CONFIRM), as biometrickitd
    // saves it when the lock state shows the password validated: the kept one would restore the lockout at the
    // next boot's load
    st.save = Some(Save { uid, acm: None, lockout: true, order: KVec::new(), next: 0, handed: None });
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
    if kind == Kind::Match && token_gone(data, uid) {
        return Err(EKEYEXPIRED);
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
    /// 0x09's flags at 0x14 (a match): proto::MATCH_CREDENTIAL_ADDED.
    flags: u32,
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
        match data.wait_lift(window, &mut || true) {
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

/// 0x09 named an identity: its result, and the user's authentication for the unlock token (token_gone).
fn match_named(data: &SepData, m: &proto::MatchResult, i: u32, o: &mut Outcome) {
    if m.user == u32::MAX {
        o.result = R_NO_MATCH;
        data.uv_misses.store(data.uv_misses.load(Relaxed).saturating_add(1), Relaxed);
        return;
    }
    data.uv_misses.store(0, Relaxed);
    if data.identity.as_ref().is_some_and(|id| id.uid == m.user) {
        data.bio_authenticated();
    }
    vinfo!(data.dev, "[sep2] bio: match image {}: 0x09 names user {}, flags {:#x}\n", i, m.user as i32, m.retry);
    o.result = R_MATCHED;
    o.flags = m.retry;
    o.uid = m.user;
    o.uuid = m.uuid;
}

/// The SEP's background operation after a capture (its template update): once its request 3 came
/// (SepData::bgops_ready), the result fetched with 0x21, as checkBgOpsResult fetches it after each 0x09 and on the
/// request (rda `AppleMesaSEPDriver_272` 0xfffffe0009ac210c). An updated template list marks the catacombs dirty; a
/// short answer leaves the request pending for the next call, as the kext's.
fn bgops_check(data: &SepData) {
    if !data.bgops_ready.load(Relaxed) {
        return;
    }
    data.bgops_ready.store(false, Relaxed);
    match data.sbio_query(proto::SBIO_BGOPS_RESULT, &[], false) {
        Some(r) if r.status == 0 && r.data.len() >= proto::BGOPS_RESULT_LEN => {
            let (present, updated) = (le16(&r.data, 0) != 0, le16(&r.data, 2) != 0);
            if updated {
                data.catacomb_dirty.store(true, Relaxed);
            }
            vinfo!(data.dev, "[sep2] bio: the background operation's result: present {}, templates updated {}\n", present, updated);
        }
        r => {
            data.bgops_ready.store(true, Relaxed);
            vinfo!(data.dev, "[sep2] bio: 0x21: {:?}, kept for the next try\n", r.map(|r| (r.status, r.data.len())));
        }
    }
}

/// How long the SEP's report of a password's unlock token may lag the REARM that gave it (its request 1 comes on its
/// own, after the key store's reply).
const TOKEN_REPORT_NS: u64 = 5_000_000_000;

/// macOS's rule for Touch ID's matches: a match needs the user's unlock token (UnlockTokenPresent 0x8 in the SEP's lock
/// state; AppleMesaSEPDriver's checkAutoMatchLockoutConditions, rda `AppleMesaSEPDriver_272` 0xfffffe0009ab8560, drops
/// a match's images without it), which only a validated password gives back: REARM, after the host accepted the
/// password. The boot's UNLOCK is no password, so before the first REARM the token is dropped (0x26); after
/// `token_lifetime` seconds with neither a REARM nor a match naming the user it goes with the biometric tokens (0x72), as
/// IOBiometricFamily's bio-token timer drops them (`bioTokenExpirationHandler` 0xfffffe000abd12a4). The age is on the
/// boot clock, so time asleep counts; it is checked as a match begins, not by a timer. True: the match is refused.
fn token_gone(data: &SepData, uid: u32) -> bool {
    let lifetime = u64::from(crate::module_parameters::token_lifetime.value());
    if lifetime == 0 {
        return false;
    }
    let lock = data.lock_state(uid);
    let held = lock.is_some_and(|l| l & proto::LOCK_UNLOCK_TOKEN != 0);
    let age = data.bio_auth_age_ns();
    let why = match age {
        None => Some((proto::SBIO_DROP_UNLOCK_TOKEN, "no password since the boot")),
        Some(a) if a > lifetime.saturating_mul(1_000_000_000) => {
            Some((proto::SBIO_DROP_BIO_TOKENS, "neither a password nor a match within token_lifetime"))
        }
        Some(_) => None,
    };
    if let Some((op, why)) = why {
        if held {
            data.sbio_drop(op, uid);
        }
        dev_info!(data.dev, "[sep2] bio: uid {}'s match refused: {}; the user's password gives Touch ID back\n", uid, why);
        return true;
    }
    // the SEP dropped the token itself (its own lifetime), past the lag of its report after a REARM
    if lock.is_some() && !held && age.is_some_and(|a| a > TOKEN_REPORT_NS) {
        dev_info!(data.dev, "[sep2] bio: uid {}'s match refused: the SEP holds no unlock token (lock state {:#x})\n", uid, lock.unwrap_or(0));
        return true;
    }
    false
}

/// A match's image as stage 14's run_match relays it: 0x23, 0x06 with the match's flags and user, 0x65, 0x07; 0x09
/// for an image usable for a match; 0x22 after. Whether the result ends the match.
fn match_relay(data: &SepData, op: &Op, i: u32, img: &[u8], ticks: u64, o: &mut Outcome) -> bool {
    // a match for a credential (verify with an ACM context): the context on every image
    let head = match op.acm {
        Some(acm) => data.relay_head(img, &proto::image_init_match_cred(0, ticks, op.uid, &acm)),
        None => data.relay_head(img, &proto::image_init_match(0, ticks, op.flags, op.uid)),
    };
    let a = match head {
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
                Some(m) if m.updated => {
                    // the match updated a template: the catacombs are saved at the end (handleMatch's dirty flag)
                    data.catacomb_dirty.store(true, Relaxed);
                    vinfo!(data.dev, "[sep2] bio: match image {}: the match updated user {}'s template\n", i, m.user as i32);
                    match_named(data, &m, i, o);
                    ended = m.user != u32::MAX;
                }
                Some(m) if m.user == u32::MAX => {
                    o.result = R_NO_MATCH;
                    data.uv_misses.store(data.uv_misses.load(Relaxed).saturating_add(1), Relaxed);
                }
                Some(m) => {
                    match_named(data, &m, i, o);
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
        // and the background operation's result, as handleMatch's checkBgOpsResult after each 0x09
        bgops_check(data);
    }
    if data.enrol_sbio(proto::SBIO_BG_OPS, &[], false).is_none() && !ended {
        o.result = R_FAILED;
        ended = true;
    }
    ended
}

/// User presence for the FIDO2 authenticator (fido.rs): one touch on the sensor within `window` ms, then its lift
/// within another `window` (SepData::wait_lift), so one touch held on answers one request. The sensor is brought up as
/// for an operation (mesa_pass) and its capture armed; the image is read and zeroed, never relayed to the SEP; then
/// the sensor idles and goes off. The capture goes on in slices of PRESENCE_SLICE_MS, `tick` called
/// after each (the host's keepalive); it returns false to stop (the host cancelled). Failed with an operation or a
/// save open, the service not ready or the sensor's error.
pub(crate) fn presence(data: &SepData, window: u32, tick: &mut dyn FnMut() -> bool) -> Presence {
    let st = data.bio_op.lock();
    if !ops_open(data) || st.op.is_some() || st.save.is_some() {
        return Presence::Failed;
    }
    data.bio_cancel.store(false, Relaxed);
    data.capture_armed.store(false, Relaxed);
    if !data.mesa_pass(true) {
        let _ = mesa::power(false);
        return Presence::Failed;
    }
    let mut got = Presence::Failed;
    if mesa::capture_arm(true).is_ok() {
        let mut waited = 0u32;
        loop {
            let w = PRESENCE_SLICE_MS.min(window - waited);
            match data.capture_image(w) {
                Ok((mut img, _, at)) => {
                    img.iter_mut().for_each(|b| *b = 0);
                    // A touch counts once it ends: a finger held on answers no second request.
                    got = match data.wait_lift(window, tick) {
                        Ok(()) => Presence::Touch,
                        Err(why) if why == crate::CAPTURE_CANCELLED => Presence::Cancelled,
                        Err(why) if why == crate::CAPTURE_NO_IMAGE => Presence::Timeout,
                        Err(why) => {
                            dev_info!(data.dev, "[sep2] bio: the presence's lift failed: {}\n", why);
                            Presence::Failed
                        }
                    };
                    dev_info!(data.dev, "[sep2] bio: a touch for presence at {} ms, {}\n", waited + at,
                              if matches!(got, Presence::Touch) { "lifted" } else { "not lifted" });
                    break;
                }
                Err(why) if why == crate::CAPTURE_NO_IMAGE && waited + w < window => {
                    waited += w;
                    if !tick() {
                        dev_info!(data.dev, "[sep2] bio: presence cancelled by the host at {} ms\n", waited);
                        got = Presence::Cancelled;
                        break;
                    }
                }
                Err(why) if why == crate::CAPTURE_NO_IMAGE => {
                    dev_info!(data.dev, "[sep2] bio: no touch for presence in {} ms\n", window);
                    got = Presence::Timeout;
                    break;
                }
                Err(why) => {
                    dev_info!(data.dev, "[sep2] bio: no touch for presence: {}\n", why);
                    break;
                }
            }
        }
    }
    data.sensor_idle("the presence check's end");
    let _ = mesa::capture_arm(false);
    let _ = mesa::power(false);
    drop(st);
    got
}

/// User verification for the FIDO2 authenticator (fido.rs): a match of the session's user, run by the driver as MATCH
/// and its CAPTUREs run it for userspace (match_relay), within `window` ms, `tick` called after each slice as in
/// presence(). A finger the SEP does not name may try again, VERIFY_TRIES in all; an image the SEP does not use for a
/// match counts as none. A match counts once the finger lifts. Unavailable with no identity this boot or the user's
/// component not loaded (libfprint's first use loads it); Failed with an operation or a save open. The lockout
/// record it changes is saved at userspace's next visit (`lockout_dirty`, SAVE_NEXT).
/// `bound`: the match is made for a credential (MATCH_CREDENTIAL_SET) in a new ACM context, which Matched hands to
/// the caller (SepData::uv_end deletes it): the SEP's key store takes it for a key whose ACL asks for the user's
/// biometry. Any other outcome deletes the context.
pub(crate) fn verify(data: &SepData, window: u32, tick: &mut dyn FnMut() -> bool, bound: bool) -> Verify {
    let Some(uid) = data.identity.as_ref().map(|id| id.uid) else {
        return Verify::Unavailable;
    };
    let st = data.bio_op.lock();
    if !ops_open(data) || st.op.is_some() || st.save.is_some() {
        return Verify::Failed;
    }
    if locked_out(data, uid) || token_gone(data, uid) {
        return Verify::LockedOut;
    }
    data.bio_cancel.store(false, Relaxed);
    data.capture_armed.store(false, Relaxed);
    if !data.mesa_pass(true) {
        let _ = mesa::power(false);
        return Verify::Failed;
    }
    let acm = if bound {
        match data.uv_context() {
            Ok(acm) => Some(acm),
            Err(why) => {
                dev_info!(data.dev, "[sep2] bio: no ACM context for user verification: {}\n", why);
                let _ = mesa::power(false);
                return Verify::Failed;
            }
        }
    } else {
        None
    };
    let flags = if bound { proto::MATCH_CREDENTIAL_SET } else { MATCH_FLAGS };
    let mut op = Op { kind: Kind::Match, uid, flags, acm, touches: 0, lift: false, ended: false, complete: false };
    let mut got = match prepare(data, Kind::Match, uid) {
        Ok(_) => None,
        Err((_, why)) => {
            dev_info!(data.dev, "[sep2] bio: no match for user verification: {}\n", why);
            let unloaded = data.components("for user verification").is_some_and(|c| !c.iter().any(|&(w, st)| w == uid as i32 && st & proto::COMPONENT_ACTIVE != 0));
            Some(if unloaded { Verify::Unavailable } else { Verify::Failed })
        }
    };
    let (mut waited, mut tries) = (0u32, 0u32);
    while got.is_none() {
        let w = PRESENCE_SLICE_MS.min(window - waited);
        match data.capture_image(w) {
            Ok((mut img, n, at)) => {
                let ticks = mesa::ticks();
                let mut o = Outcome::default();
                data.image_check_log(&img, n, at, op.touches == 0);
                let _ = match_relay(data, &op, op.touches, &img, ticks, &mut o);
                op.touches += 1;
                img.fill(0);
                drop(img);
                let mut named = o.result == R_MATCHED && o.uid == uid;
                if named && bound && o.flags & proto::MATCH_CREDENTIAL_ADDED == 0 {
                    dev_info!(data.dev, "[sep2] bio: user verification: the SEP named the user but added no credential (0x09's flags {:#x})\n", o.flags);
                    named = false;
                    o.result = R_FAILED;
                }
                let again = match o.result {
                    R_MATCHED if named => false,
                    R_RETRY => true,
                    R_MATCHED | R_NO_MATCH => {
                        tries += 1;
                        if locked_out(data, uid) {
                            got = Some(Verify::LockedOut);
                        } else if tries >= VERIFY_TRIES {
                            got = Some(Verify::NoMatch);
                        }
                        got.is_none()
                    }
                    _ => {
                        got = Some(Verify::Failed);
                        false
                    }
                };
                dev_info!(data.dev, "[sep2] bio: user verification: touch {} at {} ms: result {}{}\n", op.touches, waited + at, o.result,
                          if named { ", the session's user" } else { "" });
                if named || again {
                    match data.wait_lift(window, &mut *tick) {
                        Ok(()) if named => got = Some(Verify::Matched(acm)),
                        Ok(()) => {}
                        Err(why) if why == crate::CAPTURE_CANCELLED => got = Some(Verify::Cancelled),
                        Err(why) if why == crate::CAPTURE_NO_IMAGE => got = Some(Verify::Timeout),
                        Err(why) => {
                            dev_info!(data.dev, "[sep2] bio: user verification's lift failed: {}\n", why);
                            got = Some(Verify::Failed);
                        }
                    }
                }
            }
            Err(why) if why == crate::CAPTURE_NO_IMAGE && waited + w < window => {
                waited += w;
                if !tick() {
                    got = Some(Verify::Cancelled);
                }
            }
            Err(why) if why == crate::CAPTURE_NO_IMAGE => got = Some(Verify::Timeout),
            Err(why) if why == crate::CAPTURE_CANCELLED => got = Some(Verify::Cancelled),
            Err(why) => {
                dev_info!(data.dev, "[sep2] bio: no touch for user verification: {}\n", why);
                got = Some(Verify::Failed);
            }
        }
    }
    stop(data, &op);
    if op.touches > 0 {
        data.lockout_dirty.store(true, Relaxed);
    }
    let got = got.unwrap_or(Verify::Failed);
    if let (Some(acm), false) = (acm, matches!(got, Verify::Matched(_))) {
        data.uv_end(&acm);
    }
    drop(st);
    got
}

/// Whether verify() could run now: an identity this boot, operations open and the user not locked out. The user's
/// component is checked by verify() itself (a request to the SEP).
pub(crate) fn verify_ready(data: &SepData) -> bool {
    data.identity.as_ref().is_some() && ops_open(data)
}

/// The fingers verify() takes before it answers NoMatch: under the SEP's five to its lockout.
const VERIFY_TRIES: u32 = 3;

/// The fingers the SEP does not name in a row before it locks the user's matches out.
const LOCKOUT_MISSES: u32 = 5;

/// How many more fingers the SEP would take before its lockout, as far as the driver saw: LOCKOUT_MISSES less the
/// ones not named since the last one named or the session's last unlock; 0 once the SEP says locked out. The SEP
/// keeps the count itself and does not tell it: the misses of an earlier boot are in its record, not here, so at
/// least 1 while it is not locked out.
pub(crate) fn uv_retries(data: &SepData) -> u32 {
    let Some(uid) = data.identity.as_ref().map(|id| id.uid) else {
        return 0;
    };
    if data.lock_state(uid).is_some_and(|l| l & (proto::LOCK_BIO | proto::LOCK_PASSCODE) != 0) {
        return 0;
    }
    LOCKOUT_MISSES.saturating_sub(data.uv_misses.load(Relaxed)).max(1)
}

/// verify()'s outcome.
pub(crate) enum Verify {
    /// The SEP named the session's user, and the finger lifted; a bound verification's ACM context, which now holds
    /// the match's credential.
    Matched(Option<[u8; proto::ACM_HANDLE_LEN]>),
    /// VERIFY_TRIES fingers the SEP did not name.
    NoMatch,
    /// The SEP reports the user's matches locked out.
    LockedOut,
    /// No identity this boot, or the user's component is not loaded.
    Unavailable,
    Timeout,
    Cancelled,
    Failed,
}

/// presence()'s capture slice: CTAPHID's keepalive comes at least every 100 ms.
const PRESENCE_SLICE_MS: u32 = 100;

/// presence()'s outcome.
pub(crate) enum Presence {
    /// A touch, then its lift.
    Touch,
    /// No touch within the window, or no lift within the next.
    Timeout,
    /// `tick` asked to stop.
    Cancelled,
    Failed,
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
    bgops_check(data);
    // a match saves the catacombs only when a template changed (biometrickitd's saveCatacombIfDirty): each save's
    // master confirm writes the SEP's xART store; an enrolment always saves them
    let dirty = data.catacomb_dirty.load(Relaxed);
    data.catacomb_dirty.store(false, Relaxed);
    let order = if op.kind == Kind::Match && !dirty {
        Some(Ok(KVec::new()))
    } else {
        data.components("before the save").map(|c| crate::save_order(&c))
    };
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
    if st.save.is_none() && st.op.is_none() && data.lockout_dirty.load(Relaxed) {
        // a match the driver ran for the authenticator (verify) changed the lockout record: its save
        let uid = data.identity.as_ref().map(|id| id.uid).ok_or(ENODATA)?;
        data.lockout_dirty.store(false, Relaxed);
        bgops_check(data);
        let order = if data.catacomb_dirty.load(Relaxed) {
            data.catacomb_dirty.store(false, Relaxed);
            match data.components("before the save") {
                Some(c) => crate::save_order(&c)?,
                None => KVec::new(),
            }
        } else {
            KVec::new()
        };
        st.save = Some(Save { uid, acm: None, lockout: true, order, next: 0, handed: None });
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
        // the lockout record not kept: the next visit's SAVE_NEXT offers it again
        if s.lockout {
            data.lockout_dirty.store(true, Relaxed);
        }
    }
    if let (Some((acm, uid)), true) = (cred, ready(data)) {
        data.cred_close(&acm, uid);
        vinfo!(data.dev, "[sep2] bio: closed with an operation or a save open: dropped\n");
    }
    data.bio_cancel.store(false, Relaxed);
}
