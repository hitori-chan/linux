// SPDX-License-Identifier: GPL-2.0-only

//! The SEP's FIDO2 authenticator (`apple_sep.fido`, docs/hardware/SEP-KEYS.md): CTAP 2.0 over CTAPHID on a virtual
//! HID device (fido.c), for libfido2 and so `systemd-cryptenroll --fido2-device` and the initramfs's LUKS unlock.
//! A credential's ID carries its SEP ref key (the private half never leaves the SEP) and a 32-byte key K sealed by
//! kc_wrap (which takes 32 bytes: 96 answered -1, build 64), so only this Mac's key store opens it; an HMAC under K
//! binds the RP ID's hash and the ref key to it, and CredRandom is an HMAC under K. GetInfo, MakeCredential
//! (packed self attestation), GetAssertion with `hmac-secret`, GetNextAssertion, Reset, ClientPIN's getKeyAgreement
//! (PIN/UV protocol 1); no PIN. Resident credentials (the rk option, passkeys) add a list on the disk that finds a
//! credential by its RP (rk.rs); without one the authenticator keeps nothing. User presence is a touch on the Touch ID sensor; user verification (the uv option) a match
//! of the session's user by the SEP.

use kernel::{alloc::KVec, prelude::*};

pub(crate) mod ffi {
    use core::ffi::c_void;
    pub(crate) type Rx = unsafe extern "C" fn(ctx: *mut c_void, pkt: *const u8);
    extern "C" {
        pub(crate) fn apple_sep_fido_create(parent: *mut c_void, ctx: *mut c_void, rx: Rx) -> *mut c_void;
        pub(crate) fn apple_sep_fido_destroy(f: *mut c_void);
        pub(crate) fn apple_sep_fido_send(f: *mut c_void, pkt: *const u8) -> i32;
        pub(crate) fn apple_sep_fido_aes256_cbc(key: *const u8, encrypt: i32, buf: *mut u8, len: usize) -> i32;
        pub(crate) fn apple_sep_fido_hmac_sha256(key: *const u8, key_len: usize, data: *const u8, len: usize, out: *mut u8);
    }
}

/// HMAC-SHA-256 (lib/crypto).
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    // SAFETY: each slice is valid for its length and `o` for the 32 bytes written.
    unsafe { ffi::apple_sep_fido_hmac_sha256(key.as_ptr(), key.len(), data.as_ptr(), data.len(), o.as_mut_ptr()) };
    o
}

/// AES-256-CBC with a zero IV in place (PIN/UV protocol 1); `buf` a whole number of blocks.
pub(crate) fn aes_cbc(key: &[u8; 32], encrypt: bool, buf: &mut [u8]) -> bool {
    // SAFETY: `key` is 32 bytes, `buf` valid for its length.
    unsafe { ffi::apple_sep_fido_aes256_cbc(key.as_ptr(), i32::from(encrypt), buf.as_mut_ptr(), buf.len()) == 0 }
}

// --- CBOR, the subset CTAP2 uses ---

pub(crate) struct Cbor(pub(crate) KVec<u8>);

impl Cbor {
    pub(crate) fn new() -> Self {
        Cbor(KVec::new())
    }

    fn head(&mut self, major: u8, v: u64) -> Result {
        let m = major << 5;
        if v < 24 {
            self.0.push(m | v as u8, GFP_KERNEL)?;
        } else if v <= 0xff {
            self.0.extend_from_slice(&[m | 24, v as u8], GFP_KERNEL)?;
        } else if v <= 0xffff {
            self.0.extend_from_slice(&[m | 25, (v >> 8) as u8, v as u8], GFP_KERNEL)?;
        } else if v <= 0xffff_ffff {
            self.0.push(m | 26, GFP_KERNEL)?;
            self.0.extend_from_slice(&(v as u32).to_be_bytes(), GFP_KERNEL)?;
        } else {
            self.0.push(m | 27, GFP_KERNEL)?;
            self.0.extend_from_slice(&v.to_be_bytes(), GFP_KERNEL)?;
        }
        Ok(())
    }

    pub(crate) fn int(&mut self, v: i64) -> Result<&mut Self> {
        if v >= 0 {
            self.head(0, v as u64)?;
        } else {
            self.head(1, (-1 - v) as u64)?;
        }
        Ok(self)
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> Result<&mut Self> {
        self.head(2, b.len() as u64)?;
        self.0.extend_from_slice(b, GFP_KERNEL)?;
        Ok(self)
    }

    pub(crate) fn text(&mut self, t: &[u8]) -> Result<&mut Self> {
        self.head(3, t.len() as u64)?;
        self.0.extend_from_slice(t, GFP_KERNEL)?;
        Ok(self)
    }

    pub(crate) fn array(&mut self, n: usize) -> Result<&mut Self> {
        self.head(4, n as u64)?;
        Ok(self)
    }

    pub(crate) fn map(&mut self, n: usize) -> Result<&mut Self> {
        self.head(5, n as u64)?;
        Ok(self)
    }

    pub(crate) fn bool(&mut self, b: bool) -> Result<&mut Self> {
        self.0.push(if b { 0xf5 } else { 0xf4 }, GFP_KERNEL)?;
        Ok(self)
    }

    pub(crate) fn raw(&mut self, b: &[u8]) -> Result<&mut Self> {
        self.0.extend_from_slice(b, GFP_KERNEL)?;
        Ok(self)
    }
}

/// One CBOR item's head.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Item<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    Text(&'a [u8]),
    Array(usize),
    Map(usize),
    Bool(bool),
    Null,
}

/// A CBOR reader over a request's bytes: definite lengths only, as CTAP2's canonical form has them.
pub(crate) struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Rd { b, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let r = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(r)
    }

    fn arg(&mut self, info: u8) -> Option<u64> {
        Some(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?)),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().ok()?)),
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            _ => return None,
        })
    }

    /// The next item; an array's or a map's entries follow it.
    pub(crate) fn item(&mut self) -> Option<Item<'a>> {
        let ib = self.byte()?;
        let (major, info) = (ib >> 5, ib & 0x1f);
        if major == 7 {
            return match info {
                20 => Some(Item::Bool(false)),
                21 => Some(Item::Bool(true)),
                22 => Some(Item::Null),
                _ => None,
            };
        }
        let v = self.arg(info)?;
        Some(match major {
            0 => Item::Int(i64::try_from(v).ok()?),
            1 => Item::Int(-1 - i64::try_from(v).ok()?),
            2 => Item::Bytes(self.take(usize::try_from(v).ok()?)?),
            3 => Item::Text(self.take(usize::try_from(v).ok()?)?),
            4 => Item::Array(usize::try_from(v).ok()?),
            5 => Item::Map(usize::try_from(v).ok()?),
            _ => return None,
        })
    }

    /// Skips one whole item, nested ones included (at most 8 deep).
    pub(crate) fn skip(&mut self) -> Option<()> {
        self.skip_depth(0)
    }

    /// Skips what follows an array's or a map's head already read (a value this reader has no use for).
    pub(crate) fn skip_rest(&mut self, head: &Item<'_>) -> Option<()> {
        match head {
            Item::Array(n) => (0..*n).try_for_each(|_| self.skip_depth(1)),
            Item::Map(n) => (0..n.checked_mul(2)?).try_for_each(|_| self.skip_depth(1)),
            _ => Some(()),
        }
    }

    fn skip_depth(&mut self, depth: u32) -> Option<()> {
        if depth > 8 {
            return None;
        }
        match self.item()? {
            Item::Array(n) => (0..n).try_for_each(|_| self.skip_depth(depth + 1)),
            // a count of up to 2^64 - 1 pairs is the request's to give: no overflow (it panics under
            // CONFIG_RUST_OVERFLOW_CHECKS), and the walk ends with the message
            Item::Map(n) => (0..n.checked_mul(2)?).try_for_each(|_| self.skip_depth(depth + 1)),
            _ => Some(()),
        }
    }
}

// --- CTAP ---

pub(crate) const ERR_INVALID_COMMAND: u8 = 0x01;
pub(crate) const ERR_INVALID_PARAMETER: u8 = 0x02;
pub(crate) const ERR_INVALID_LENGTH: u8 = 0x03;
pub(crate) const ERR_INVALID_SEQ: u8 = 0x04;
pub(crate) const ERR_CHANNEL_BUSY: u8 = 0x06;
pub(crate) const ERR_INVALID_CHANNEL: u8 = 0x0b;
pub(crate) const ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub(crate) const ERR_INVALID_CBOR: u8 = 0x12;
pub(crate) const ERR_MISSING_PARAMETER: u8 = 0x14;
pub(crate) const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub(crate) const ERR_OPERATION_DENIED: u8 = 0x27;
pub(crate) const ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;
pub(crate) const ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
pub(crate) const ERR_NO_CREDENTIALS: u8 = 0x2e;
pub(crate) const ERR_PIN_INVALID: u8 = 0x31;
pub(crate) const ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub(crate) const ERR_PIN_NOT_SET: u8 = 0x35;
pub(crate) const ERR_PUAT_REQUIRED: u8 = 0x36;
pub(crate) const ERR_UNAUTHORIZED_PERMISSION: u8 = 0x40;
pub(crate) const ERR_UV_BLOCKED: u8 = 0x3c;
pub(crate) const ERR_UV_INVALID: u8 = 0x3f;
pub(crate) const ERR_KEY_STORE_FULL: u8 = 0x28;
pub(crate) const ERR_NOT_ALLOWED: u8 = 0x30;
pub(crate) const ERR_OTHER: u8 = 0x7f;

const CMD_PING: u8 = 0x81;
const CMD_INIT: u8 = 0x86;
const CMD_CBOR: u8 = 0x90;
const CMD_CANCEL: u8 = 0x91;
pub(crate) const CMD_KEEPALIVE: u8 = 0xbb;
pub(crate) const CMD_ERROR: u8 = 0xbf;
/// KEEPALIVE's status while the authenticator waits for the user's touch.
pub(crate) const KEEPALIVE_UPNEEDED: u8 = 2;
/// A request the host cancelled while it waited for the touch.
pub(crate) const ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
const BROADCAST: u32 = 0xffff_ffff;
/// The largest message taken (GetInfo's maxMsgSize): CTAPHID's own limit, so an allow list of several of our
/// credential IDs (some 340 bytes each) fits.
pub(crate) const MAX_MSG: usize = 7609;

/// CTAPHID's state: the channels handed out and one message being reassembled.
pub(crate) struct Hid {
    next_cid: u32,
    cid: u32,
    cmd: u8,
    want: usize,
    seq: u8,
    buf: KVec<u8>,
}

/// What a packet asks of the authenticator once its message is whole.
pub(crate) enum Msg {
    None,
    /// An answer ready to send (an error, PING's echo, INIT's reply).
    Reply(u32, u8, KVec<u8>),
    /// A CTAP2 request on `cid`.
    Cbor(u32, KVec<u8>),
    /// CANCEL on `cid`: the request in flight there ends.
    Cancel(u32),
}

impl Hid {
    pub(crate) fn new() -> Self {
        Hid { next_cid: 1, cid: 0, cmd: 0, want: 0, seq: 0, buf: KVec::new() }
    }

    fn error(cid: u32, code: u8) -> Msg {
        let mut v = KVec::new();
        if v.push(code, GFP_KERNEL).is_err() {
            return Msg::None;
        }
        Msg::Reply(cid, CMD_ERROR, v)
    }

    /// One 64-byte packet from the host.
    pub(crate) fn packet(&mut self, p: &[u8; 64]) -> Msg {
        let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        if cid == 0 {
            return Self::error(cid, ERR_INVALID_CHANNEL);
        }
        if p[4] & 0x80 == 0 {
            // a continuation
            if self.want == 0 || cid != self.cid {
                return Msg::None;
            }
            if p[4] != self.seq {
                self.want = 0;
                return Self::error(cid, ERR_INVALID_SEQ);
            }
            self.seq += 1;
            let n = (self.want - self.buf.len()).min(59);
            if self.buf.extend_from_slice(&p[5..5 + n], GFP_KERNEL).is_err() {
                self.want = 0;
                return Self::error(cid, ERR_OTHER);
            }
            return self.whole();
        }
        let cmd = p[4];
        let len = usize::from(u16::from_be_bytes([p[5], p[6]]));
        if cmd == CMD_INIT {
            // INIT aborts any transaction on its channel
            if cid == self.cid {
                self.want = 0;
            }
            if len != 8 {
                return Self::error(cid, ERR_INVALID_LENGTH);
            }
            let new = if cid == BROADCAST {
                let c = self.next_cid;
                self.next_cid = self.next_cid.wrapping_add(1).max(1);
                if self.next_cid == BROADCAST {
                    self.next_cid = 1;
                }
                c
            } else {
                cid
            };
            let mut v = KVec::new();
            // the nonce, the channel, protocol 2, version 1.0.0, capabilities CBOR (4) and NMSG (8)
            let ok = v.extend_from_slice(&p[7..15], GFP_KERNEL).is_ok()
                && v.extend_from_slice(&new.to_be_bytes(), GFP_KERNEL).is_ok()
                && v.extend_from_slice(&[2, 1, 0, 0, 0x0c], GFP_KERNEL).is_ok();
            return if ok { Msg::Reply(cid, CMD_INIT, v) } else { Msg::None };
        }
        if cid == BROADCAST {
            return Self::error(cid, ERR_INVALID_CHANNEL);
        }
        if cmd == CMD_CANCEL {
            return Msg::Cancel(cid);
        }
        if self.want != 0 && cid != self.cid {
            return Self::error(cid, ERR_CHANNEL_BUSY);
        }
        if len == 0 || len > MAX_MSG {
            self.want = 0;
            return Self::error(cid, ERR_INVALID_LENGTH);
        }
        self.cid = cid;
        self.cmd = cmd;
        self.want = len;
        self.seq = 0;
        self.buf.clear();
        let n = len.min(57);
        if self.buf.extend_from_slice(&p[7..7 + n], GFP_KERNEL).is_err() {
            self.want = 0;
            return Self::error(cid, ERR_OTHER);
        }
        self.whole()
    }

    fn whole(&mut self) -> Msg {
        if self.buf.len() < self.want {
            return Msg::None;
        }
        self.want = 0;
        let data = core::mem::replace(&mut self.buf, KVec::new());
        match self.cmd {
            CMD_PING => Msg::Reply(self.cid, CMD_PING, data),
            CMD_CBOR => Msg::Cbor(self.cid, data),
            _ => Self::error(self.cid, ERR_INVALID_COMMAND),
        }
    }

    /// `data` framed for `cid`: each 64-byte packet handed to `send`.
    pub(crate) fn frame(cid: u32, cmd: u8, data: &[u8], mut send: impl FnMut(&[u8; 64])) {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = cmd;
        p[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let n = data.len().min(57);
        p[7..7 + n].copy_from_slice(&data[..n]);
        send(&p);
        let mut at = n;
        let mut seq = 0u8;
        while at < data.len() {
            let mut c = [0u8; 64];
            c[..4].copy_from_slice(&cid.to_be_bytes());
            c[4] = seq;
            let n = (data.len() - at).min(59);
            c[5..5 + n].copy_from_slice(&data[at..at + n]);
            send(&c);
            at += n;
            seq += 1;
        }
    }
}

/// CTAPHID's command byte for a CTAP2 reply.
pub(crate) const REPLY_CBOR: u8 = CMD_CBOR;

/// The authenticator's model, in GetInfo and each credential's attested data (not a device ID).
pub(crate) const AAGUID: [u8; 16] = *b"apple-sep-fido-1";

/// A P-256 public key in COSE (RFC 9053): kty EC2, `alg`, crv P-256, x, y; from X9.63's `04 ‖ X ‖ Y`.
pub(crate) fn cose_p256(c: &mut Cbor, alg: i64, point: &[u8]) -> Result {
    if point.len() != 65 || point[0] != 4 {
        return Err(EINVAL);
    }
    c.map(5)?.int(1)?.int(2)?.int(3)?.int(alg)?.int(-1)?.int(1)?.int(-2)?.bytes(&point[1..33])?.int(-3)?.bytes(&point[33..65])?;
    Ok(())
}

/// A COSE P-256 key's point as X9.63 `04 ‖ X ‖ Y` (the platform's key agreement key).
pub(crate) fn cose_point(rd: &mut Rd<'_>) -> Option<[u8; 65]> {
    let Item::Map(n) = rd.item()? else { return None };
    let mut p = [0u8; 65];
    p[0] = 4;
    let (mut x, mut y) = (false, false);
    for _ in 0..n {
        let k = rd.item()?;
        match (k, rd.item()?) {
            (Item::Int(-2), Item::Bytes(b)) if b.len() == 32 => {
                p[1..33].copy_from_slice(b);
                x = true;
            }
            (Item::Int(-3), Item::Bytes(b)) if b.len() == 32 => {
                p[33..65].copy_from_slice(b);
                y = true;
            }
            (Item::Int(-1), Item::Int(crv)) if crv != 1 => return None,
            (_, Item::Array(_) | Item::Map(_)) => return None,
            _ => {}
        }
    }
    (x && y).then_some(p)
}

// --- CTAP2 ---

/// What the authenticator needs of the SEP (sep.rs): a P-256 ref key made, signing with it and its ECDH; sealing
/// to this Mac; user presence; random bytes.
pub(crate) trait Keys {
    /// A new ref key: its blob and its public point (X9.63).
    fn key_create(&self) -> Option<(KVec<u8>, [u8; 65])>;
    /// A DER ECDSA signature of `digest` by the ref key `blob`.
    fn key_sign(&self, blob: &[u8], digest: &[u8; 32]) -> Option<KVec<u8>>;
    /// The X of the ref key `blob` times `peer` (X9.63).
    fn key_ecdh(&self, blob: &[u8], peer: &[u8; 65]) -> Option<[u8; 32]>;
    fn seal(&self, data: &[u8]) -> Option<KVec<u8>>;
    fn unseal(&self, blob: &[u8]) -> Option<KVec<u8>>;
    /// Whether the user is present, a touch on the Touch ID sensor; else the CTAP status: USER_ACTION_TIMEOUT with no
    /// touch in time, KEEPALIVE_CANCEL when the host cancelled, OPERATION_DENIED when the sensor could not ask.
    fn presence(&self) -> core::result::Result<(), u8>;
    /// Whether the user is the session's, a finger the SEP matches (which is presence too); else the CTAP status:
    /// UV_INVALID for fingers it does not name, UV_BLOCKED when it locked the matches out, UNSUPPORTED_OPTION with
    /// no session or prints loaded, and presence()'s.
    /// `bound`: the match is made for a credential, and Ok holds the ACM context it went into, for key_ecdh_uv and
    /// then uv_end.
    fn verify(&self, bound: bool) -> core::result::Result<Option<[u8; 16]>, u8>;
    /// Whether verify() can run: the user's session is unlocked this boot.
    fn uv_ready(&self) -> bool;
    /// How many more fingers the SEP would refuse before it locks the matches out, as far as is known; 0: locked out.
    fn uv_retries(&self) -> u32;
    /// Whether credentials made with a user verification get a bound key (key_create_uv).
    fn uv_bind(&self) -> bool;
    /// A new ref key the SEP uses for an ECDH, or with `sign` for a signature, only with a match's credential in the
    /// request's ACM context (its ACL): its blob and public point.
    fn key_create_uv(&self, sign: bool) -> Option<(KVec<u8>, [u8; 65])>;
    /// key_sign with a bound signing key and the ACM context of a bound verify().
    fn key_sign_uv(&self, blob: &[u8], digest: &[u8; 32], acm: &[u8; 16]) -> Option<KVec<u8>>;
    /// key_ecdh with a bound key and the ACM context of a bound verify().
    fn key_ecdh_uv(&self, blob: &[u8], peer: &[u8; 65], acm: &[u8; 16]) -> Option<[u8; 32]>;
    /// A bound verify()'s ACM context deleted.
    fn uv_end(&self, acm: &[u8; 16]);
    fn random(&self, buf: &mut [u8]);
    /// A ref key blob's public point (X9.63).
    fn key_public(&self, blob: &[u8]) -> Option<[u8; 65]>;
    /// Whether resident credentials can be kept: the store's directory is there (rk.rs, store.c).
    fn store_ok(&self) -> bool;
    /// One of the store's two files whole: None with no such file, Err when it could not be read.
    fn store_read(&self, slot: u8) -> core::result::Result<Option<KVec<u8>>, ()>;
    /// One of the store's two files written and synced.
    fn store_write(&self, slot: u8, data: &[u8]) -> bool;
    /// Seconds on a clock that only goes on, for GetNextAssertion's 30 s.
    fn now_s(&self) -> u64;
}

/// The authenticator's CTAP2 state: the key agreement key of ClientPIN (a ref key made at the first use). CTAPHID's
/// own (Hid) is apart, so packets are parsed while a request waits for the user.
pub(crate) struct Auth {
    ka: Option<(KVec<u8>, [u8; 65])>,
    /// The resident credentials.
    store: crate::rk::Store,
    /// What GetNextAssertion answers from: the last GetAssertion's other credentials.
    next: Option<Next>,
    /// The pinUvAuthToken (CTAP 2.1), given after a built-in user verification.
    token: Option<Token>,
    /// A credential management enumeration under way, and the channel of the last request (the one that began it).
    walk: Option<Walk>,
    walk_cid: u32,
    /// When the authenticator started (Keys::now_s): Reset is taken only shortly after.
    started: u64,
}

/// A key agreement's shared secret under PIN/UV protocol 1 (SHA-256 of the ECDH's X: AES-256-CBC with a zero IV, the
/// HMAC cut to 16 bytes) or 2 (HKDF-SHA-256 of X with a zero salt into an HMAC key and an AES key: a random IV
/// before the ciphertext, the HMAC whole).
enum Shared {
    One([u8; 32]),
    Two { mac: [u8; 32], aes: [u8; 32] },
}

impl Shared {
    fn new(proto: i64, z: &[u8; 32]) -> Option<Shared> {
        match proto {
            1 => Some(Shared::One(crate::sks::sha256(z))),
            2 => {
                let mut prk = hmac(&[0u8; 32], z);
                let two = Shared::Two { mac: hmac(&prk, b"CTAP2 HMAC key\x01"), aes: hmac(&prk, b"CTAP2 AES key\x01") };
                prk.fill(0);
                Some(two)
            }
            _ => None,
        }
    }

    /// The protocol's verify() of `tag` over `msg`.
    fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        match self {
            Shared::One(key) => same(&hmac(key, msg)[..16], tag),
            Shared::Two { mac, .. } => same(&hmac(mac, msg), tag),
        }
    }

    /// The protocol's decrypt(): whole blocks, after protocol 2's IV.
    fn decrypt(&self, ct: &[u8]) -> Option<KVec<u8>> {
        let (key, iv, body) = match self {
            Shared::One(key) => (key, None, ct),
            Shared::Two { aes, .. } => (aes, Some(ct.get(..16)?), ct.get(16..)?),
        };
        if body.is_empty() || body.len() % 16 != 0 {
            return None;
        }
        let mut v = KVec::new();
        v.extend_from_slice(body, GFP_KERNEL).ok()?;
        if !aes_cbc(key, false, &mut v) {
            return None;
        }
        // aes_cbc's IV is zero: the first block's is XORed in here
        if let Some(iv) = iv {
            v.iter_mut().zip(iv).for_each(|(b, i)| *b ^= i);
        }
        Some(v)
    }

    /// The protocol's encrypt() of whole blocks: protocol 2's random IV, then the ciphertext.
    fn encrypt(&self, k: &dyn Keys, pt: &[u8]) -> Option<KVec<u8>> {
        if pt.is_empty() || pt.len() % 16 != 0 {
            return None;
        }
        let mut out = KVec::new();
        let key = match self {
            Shared::One(key) => {
                out.extend_from_slice(pt, GFP_KERNEL).ok()?;
                key
            }
            Shared::Two { aes, .. } => {
                let mut iv = [0u8; 16];
                k.random(&mut iv);
                out.extend_from_slice(&iv, GFP_KERNEL).ok()?;
                out.extend_from_slice(pt, GFP_KERNEL).ok()?;
                out[16..32].iter_mut().zip(&iv).for_each(|(b, i)| *b ^= i);
                aes
            }
        };
        let at = out.len() - pt.len();
        if !aes_cbc(key, true, &mut out[at..]) {
            out.iter_mut().for_each(|b| *b = 0);
            return None;
        }
        Some(out)
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        match self {
            Shared::One(key) => key.fill(0),
            Shared::Two { mac, aes } => {
                mac.fill(0);
                aes.fill(0);
            }
        }
    }
}

/// The token's permissions: MakeCredential, GetAssertion, credential management.
const PERM_MC: u8 = 1;
const PERM_GA: u8 = 2;
const PERM_CM: u8 = 4;
/// A token is first used within 30 s and for 10 minutes at most.
const TOKEN_FIRST_S: u64 = 30;
const TOKEN_MAX_S: u64 = 600;
/// Reset is taken this long after the authenticator's start.
const RESET_S: u64 = 10;

/// The pinUvAuthToken of getPinUvAuthTokenUsingUvWithPermissions: the platform holds it (sent under the key
/// agreement's secret) and proves a request with its HMAC, which stands for the user verification that gave it.
struct Token {
    value: [u8; 32],
    permissions: u8,
    /// The RP the token is for: given with it, or its first use's.
    rp: Option<[u8; 32]>,
    since: u64,
    used: bool,
    /// The verification's touch still counts as the user's presence.
    up: bool,
    /// The ACM context the verification's match went into (a bound verify), for a credential's bound key.
    acm: Option<[u8; 16]>,
    /// The PIN/UV protocol it was given under: its pinUvAuthParams are that protocol's.
    proto: u8,
}

/// One credential of a credential management enumeration.
struct Listed {
    id: KVec<u8>,
    user: (KVec<u8>, KVec<u8>, KVec<u8>),
    public: [u8; 65],
    protect: u8,
}

/// A credential management enumeration: the RPs (each ID and its hash) or one RP's credentials, and how many went.
enum Walk {
    Rps(KVec<(KVec<u8>, [u8; 32])>, usize),
    Creds(KVec<Listed>, usize),
}

/// A credential GetAssertion found: its ID, and for a resident one the user's handle, name and display name.
struct Found {
    id: KVec<u8>,
    user: Option<(KVec<u8>, KVec<u8>, KVec<u8>)>,
    /// Its key signs only with a match's ACM context (CRED_SIGN_BOUND).
    sign_bound: bool,
}

/// A bound verification's ACM context, deleted when this goes unless it was taken out.
struct UvCtx<'k> {
    k: &'k dyn Keys,
    acm: Option<[u8; 16]>,
}

impl Drop for UvCtx<'_> {
    fn drop(&mut self) {
        if let Some(acm) = self.acm.take() {
            self.k.uv_end(&acm);
        }
    }
}

/// A GetAssertion with more credentials than the one it answered: the request's parts and the credentials left.
struct Next {
    rp_hash: [u8; 32],
    cdh: [u8; 32],
    flags: u8,
    names: bool,
    rest: KVec<Found>,
    at: usize,
    since: u64,
    /// The verification's ACM context, for the credentials whose keys sign only with it; `own`: deleted with this
    /// (a token that lives on keeps its own).
    acm: Option<[u8; 16]>,
    own: bool,
    /// The channel the GetAssertion came on.
    cid: u32,
}

/// An opened credential: its ref key and CredRandom.
struct Cred<'a> {
    key: &'a [u8],
    random: [u8; 32],
    /// CredRandom after a user verification: another secret, so one made with a finger is not had without it
    /// (CTAP 2.1's CredRandomWithUV).
    random_uv: [u8; 32],
    /// A resident credential's (CRED_RESIDENT).
    resident: bool,
    /// Its credProtect level, 1 to 3.
    protect: u8,
    /// Its key signs only with a match's ACM context (CRED_SIGN_BOUND).
    sign_bound: bool,
    /// Its bound key and the point its ECDH is taken with (CRED_UV_KEY): after a user verification CredRandom is an
    /// HMAC under `random_uv` of that ECDH's X, which the SEP computes only with the match's credential.
    uv_key: Option<(&'a [u8], [u8; 65])>,
}

pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// A credential ID's first byte. 2 (r202's): the sealed K, the binding tag, the key blob. 5: a flags byte before
/// them, bound by the tag.
const CRED_VERSION: u8 = 2;
const CRED_VERSION_FLAGS: u8 = 5;
/// A resident credential: it answers only while the store lists it, so one deleted or reset is gone for an allow
/// list too.
const CRED_RESIDENT: u8 = 0x01;
/// The credProtect level less one, in bits 1-2: 0 none asked or userVerificationOptional, 1
/// userVerificationOptionalWithCredentialIDList (no answer without a list unless the user is verified), 2
/// userVerificationRequired (no answer unless the user is verified).
const CRED_PROTECT_SHIFT: u8 = 1;
const CRED_PROTECT_MASK: u8 = 0x06;
/// Made with a user verification while uv_bind(): after the key blob come u16 the bound key's length, the bound key
/// (Keys::key_create_uv) and the 65-byte point of its ECDH, bound by the tag with the rest.
const CRED_UV_KEY: u8 = 0x08;
/// A credProtect 3 credential made while uv_bind(): its own key signs only with a match's credential in the
/// request's ACM context (Keys::key_create_uv with `sign`), so the SEP holds userVerificationRequired itself.
const CRED_SIGN_BOUND: u8 = 0x10;
const TAG_LABEL: &[u8] = b"apple-sep-fido bind";
const TAG_FLAGS_LABEL: &[u8] = b"apple-sep-fido bin5";
const RANDOM_LABEL: &[u8] = b"apple-sep-fido hmac-secret";
/// CredRandom's label after a user verification.
const RANDOM_UV_LABEL: &[u8] = b"apple-sep-fido hmac-secret uv";
/// The authenticator data's UV flag.
const FLAG_UV: u8 = 0x04;

/// The credential's binding: HMAC-SHA-256 under K of the label, the RP ID's hash and the ref key's SHA-256.
fn bind_tag(key: &[u8; 32], rp: &[u8; 32], blob: &[u8]) -> [u8; 32] {
    let mut m = [0u8; 19 + 64];
    m[..19].copy_from_slice(TAG_LABEL);
    m[19..51].copy_from_slice(rp);
    m[51..].copy_from_slice(&crate::sks::sha256(blob));
    hmac(key, &m)
}

/// A version 5 credential's binding: bind_tag's inputs under its own label, with the flags.
fn bind_tag_flags(key: &[u8; 32], rp: &[u8; 32], blob: &[u8], flags: u8, uv_key: Option<(&[u8], &[u8; 65])>) -> [u8; 32] {
    let mut m = [0u8; 19 + 1 + 128];
    m[..19].copy_from_slice(TAG_FLAGS_LABEL);
    m[19] = flags;
    m[20..52].copy_from_slice(rp);
    m[52..84].copy_from_slice(&crate::sks::sha256(blob));
    match uv_key {
        Some((bound, peer)) => {
            m[84..116].copy_from_slice(&crate::sks::sha256(bound));
            m[116..].copy_from_slice(&crate::sks::sha256(peer));
            hmac(key, &m)
        }
        None => hmac(key, &m[..84]),
    }
}

impl Auth {
    pub(crate) fn new(started: u64) -> Self {
        Auth { ka: None, store: crate::rk::Store::new(), next: None, token: None, walk: None, walk_cid: 0, started }
    }

    /// A CTAP2 request (command byte, CBOR): the status byte, then the CBOR reply.
    pub(crate) fn request(&mut self, k: &dyn Keys, cid: u32, req: &[u8]) -> KVec<u8> {
        let (cmd, body) = match req.split_first() {
            Some((c, b)) => (*c, b),
            None => (0, &[][..]),
        };
        let mut out = Cbor::new();
        // what the clock ended, and what another command or channel ends: GetNextAssertion's state and a credential
        // management enumeration belong to the channel that began them
        let now = k.now_s();
        if self.token.as_ref().is_some_and(|t| now.saturating_sub(t.since) > if t.used { TOKEN_MAX_S } else { TOKEN_FIRST_S }) {
            self.token_drop(k);
        }
        if cmd != 0x08 || self.next.as_ref().is_some_and(|n| n.cid != cid || now.saturating_sub(n.since) > 30) {
            self.next_drop(k);
        }
        if (cmd != 0x0a && cmd != 0x41) || self.walk_cid != cid {
            self.walk = None;
        }
        self.walk_cid = cid;
        let status = match cmd {
            0x04 => self.get_info(k, &mut out),
            0x01 => self.make_credential(k, body, &mut out),
            0x02 => self.get_assertion(k, body, &mut out),
            0x06 => self.client_pin(k, body, &mut out),
            0x07 => self.reset(k, now.saturating_sub(self.started)),
            0x08 => self.next_assertion(k, &mut out),
            // credential management, and its number before CTAP 2.1 was final, which libfido2 may still send
            0x0a | 0x41 => self.cred_mgmt(k, body, &mut out),
            // Selection: a touch picks this authenticator among several
            0x0b => k.presence(),
            _ => Err(ERR_INVALID_COMMAND),
        };
        let mut v = KVec::new();
        match status {
            Ok(()) => {
                if v.push(0, GFP_KERNEL).is_err() || v.extend_from_slice(&out.0, GFP_KERNEL).is_err() {
                    v.clear();
                    let _ = v.push(ERR_OTHER, GFP_KERNEL);
                }
            }
            Err(e) => {
                let _ = v.push(e, GFP_KERNEL);
            }
        }
        v
    }

    fn get_info(&self, k: &dyn Keys, o: &mut Cbor) -> core::result::Result<(), u8> {
        // uv: built-in user verification, true once the user's session is unlocked (false: capable, not ready)
        let uv = k.uv_ready();
        // rk: resident credentials, where the store's directory is there
        let rk = k.store_ok();
        // pinUvAuthToken: the token by the built-in verification; makeCredUvNotRqd: a credential that is not resident
        // is made with a touch alone; credMgmt with the resident credentials
        let mut r = || -> Result {
            o.map(6)?;
            o.int(1)?.array(2)?.text(b"FIDO_2_0")?.text(b"FIDO_2_1")?;
            o.int(2)?.array(2)?.text(b"credProtect")?.text(b"hmac-secret")?;
            o.int(3)?.bytes(&AAGUID)?;
            // no clientPin: the option says a PIN can be set, and none can
            o.int(4)?.map(7)?;
            o.text(b"rk")?.bool(rk)?.text(b"up")?.bool(true)?.text(b"uv")?.bool(uv)?;
            o.text(b"plat")?.bool(false)?.text(b"credMgmt")?.bool(rk)?;
            o.text(b"pinUvAuthToken")?.bool(true)?.text(b"makeCredUvNotRqd")?.bool(true)?;
            o.int(5)?.int(MAX_MSG as i64)?;
            o.int(6)?.array(2)?.int(2)?.int(1)?;
            Ok(())
        };
        r().map_err(|_| ERR_OTHER)
    }

    /// The key agreement key, made at its first use.
    fn ka(&mut self, k: &dyn Keys) -> core::result::Result<(), u8> {
        if self.ka.is_none() {
            self.ka = Some(k.key_create().ok_or(ERR_OTHER)?);
        }
        Ok(())
    }

    fn client_pin(&mut self, k: &dyn Keys, body: &[u8], o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut rd = Rd::new(body);
        let Some(Item::Map(n)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
        let (mut proto, mut sub, mut peer, mut permissions, mut rp) = (None, None, None, None, None);
        for _ in 0..n {
            let key = rd.item().ok_or(ERR_INVALID_CBOR)?;
            match key {
                Item::Int(1) => match rd.item() {
                    Some(Item::Int(p)) => proto = Some(p),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                Item::Int(2) => match rd.item() {
                    Some(Item::Int(s)) => sub = Some(s),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                Item::Int(3) => peer = Some(cose_point(&mut rd).ok_or(ERR_INVALID_PARAMETER)?),
                Item::Int(9) => match rd.item() {
                    Some(Item::Int(p)) => permissions = Some(p),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                Item::Int(10) => match rd.item() {
                    Some(Item::Text(t)) => rp = Some(t),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        let sub = sub.ok_or(ERR_MISSING_PARAMETER)?;
        // getRetries and getUVRetries need name no protocol (CTAP 2.1, 6.5.5.2 and 6.5.5.3; Firefox names none)
        let proto = match proto {
            Some(p) => p,
            None if sub == 1 || sub == 7 => 1,
            None => return Err(ERR_MISSING_PARAMETER),
        };
        if proto != 1 && proto != 2 {
            return Err(ERR_INVALID_PARAMETER);
        }
        match sub {
            // getRetries
            1 => (|| -> Result { o.map(1)?.int(3)?.int(8)?; Ok(()) })().map_err(|_| ERR_OTHER),
            // getKeyAgreement: alg ECDH-ES+HKDF-256, as CTAP 2.0 names it
            2 => {
                self.ka(k)?;
                let pt = self.ka.as_ref().map(|(_, p)| *p).ok_or(ERR_OTHER)?;
                (|| -> Result {
                    o.map(1)?.int(1)?;
                    cose_p256(o, -25, &pt)
                })()
                .map_err(|_| ERR_OTHER)
            }
            // getPinUvAuthTokenUsingUvWithPermissions: a user verification, then a new token for the permissions asked
            // (and the RP, which MakeCredential and GetAssertion need), encrypted under the key agreement's secret
            6 => {
                let peer = peer.ok_or(ERR_MISSING_PARAMETER)?;
                let permissions = permissions.ok_or(ERR_MISSING_PARAMETER)?;
                if permissions <= 0 {
                    return Err(ERR_INVALID_PARAMETER);
                }
                if permissions & !i64::from(PERM_MC | PERM_GA | PERM_CM) != 0 {
                    return Err(ERR_UNAUTHORIZED_PERMISSION);
                }
                let permissions = permissions as u8;
                if permissions & (PERM_MC | PERM_GA) != 0 && rp.is_none() {
                    return Err(ERR_MISSING_PARAMETER);
                }
                if !k.uv_ready() {
                    return Err(ERR_NOT_ALLOWED);
                }
                self.ka(k)?;
                let (ka, _) = self.ka.as_ref().ok_or(ERR_OTHER)?;
                let mut z = k.key_ecdh(ka, &peer).ok_or(ERR_INVALID_PARAMETER)?;
                let shared = Shared::new(proto, &z);
                z.fill(0);
                let shared = shared.ok_or(ERR_INVALID_PARAMETER)?;
                self.token_drop(k);
                // the token keeps the match's ACM context, for a credential's bound keys
                let acm = k.verify(k.uv_bind())?;
                let mut value = [0u8; 32];
                k.random(&mut value);
                let Some(enc) = shared.encrypt(k, &value) else {
                    value.fill(0);
                    if let Some(acm) = acm {
                        k.uv_end(&acm);
                    }
                    return Err(ERR_OTHER);
                };
                self.token = Some(Token { value, permissions, rp: rp.map(crate::sks::sha256), since: k.now_s(), used: false, up: true, acm, proto: proto as u8 });
                value.fill(0);
                (|| -> Result { o.map(1)?.int(2)?.bytes(&enc)?; Ok(()) })().map_err(|_| ERR_OTHER)
            }
            // getUVRetries: the SEP keeps the count (five failed matches to its lockout) and does not tell it, so
            // the driver's own count of them
            7 => {
                let left = i64::from(k.uv_retries());
                (|| -> Result { o.map(1)?.int(5)?.int(left)?; Ok(()) })().map_err(|_| ERR_OTHER)
            }
            _ => Err(ERR_PIN_NOT_SET),
        }
    }

    /// GetNextAssertion's state forgotten, and the ACM context kept with it deleted.
    fn next_drop(&mut self, k: &dyn Keys) {
        if let Some(acm) = self.next.take().and_then(|n| n.acm.filter(|_| n.own)) {
            k.uv_end(&acm);
        }
    }

    /// The token forgotten, and the ACM context kept with it deleted.
    fn token_drop(&mut self, k: &dyn Keys) {
        if let Some(mut t) = self.token.take() {
            t.value.fill(0);
            if let Some(acm) = t.acm {
                k.uv_end(&acm);
            }
        }
    }

    /// A request's pinUvAuthParam checked against the token: a live token with `perm`, for `rp` when it names one
    /// (a token without an RP takes the first it is used for), and its HMAC over `msg` as the token's protocol has
    /// it. Ok: whether the verification's touch still counts as the user's presence.
    fn token_check(&mut self, k: &dyn Keys, proto: i64, param: &[u8], msg: &[&[u8]], perm: u8, rp: Option<&[u8; 32]>) -> core::result::Result<bool, u8> {
        let now = k.now_s();
        let live = self.token.as_ref().is_some_and(|t| now.saturating_sub(t.since) <= if t.used { TOKEN_MAX_S } else { TOKEN_FIRST_S });
        if !live {
            self.token_drop(k);
            return Err(ERR_PIN_AUTH_INVALID);
        }
        let t = self.token.as_mut().ok_or(ERR_PIN_AUTH_INVALID)?;
        let mut m = KVec::new();
        for part in msg {
            m.extend_from_slice(part, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        }
        // protocol 1's HMAC is cut to 16 bytes, protocol 2's is whole
        let tag = hmac(&t.value, &m);
        if i64::from(t.proto) != proto || !same(if proto == 2 { &tag[..] } else { &tag[..16] }, param) || t.permissions & perm == 0 {
            return Err(ERR_PIN_AUTH_INVALID);
        }
        match (t.rp, rp) {
            (Some(have), Some(want)) if &have != want => return Err(ERR_PIN_AUTH_INVALID),
            (None, Some(want)) => t.rp = Some(*want),
            _ => {}
        }
        t.used = true;
        // the verification's touch stands for the presence for 30 s
        Ok(t.up && now.saturating_sub(t.since) <= TOKEN_FIRST_S)
    }

    /// A credential ID of ours for `rp` (its SHA-256), opened: the version (2, or 5 and the flags byte), u16 the
    /// sealed K's length, the sealed K, the 32-byte binding tag (bind_tag, bind_tag_flags), u16 the key blob's
    /// length, the key blob.
    fn open<'a>(k: &dyn Keys, id: &'a [u8], rp: &[u8; 32]) -> Option<Cred<'a>> {
        let (&v, rest) = id.split_first()?;
        let (flags, rest) = match v {
            CRED_VERSION => (None, rest),
            CRED_VERSION_FLAGS => {
                let (&f, rest) = rest.split_first()?;
                if f & !(CRED_RESIDENT | CRED_PROTECT_MASK | CRED_UV_KEY | CRED_SIGN_BOUND) != 0 || f & CRED_PROTECT_MASK == CRED_PROTECT_MASK {
                    return None;
                }
                (Some(f), rest)
            }
            _ => return None,
        };
        let n = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let sealed = rest.get(2..2 + n)?;
        let tag = rest.get(2 + n..2 + n + 32)?;
        let rest = rest.get(2 + n + 32..)?;
        let m = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let key = rest.get(2..2 + m)?;
        let uv_key = if flags.is_some_and(|f| f & CRED_UV_KEY != 0) {
            let rest = rest.get(2 + m..)?;
            let l = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
            let bound = rest.get(2..2 + l)?;
            let peer: [u8; 65] = rest.get(2 + l..)?.try_into().ok()?;
            Some((bound, peer))
        } else if rest.len() != 2 + m {
            return None;
        } else {
            None
        };
        let mut plain = k.unseal(sealed)?;
        let mut kk = [0u8; 32];
        if plain.len() == 32 {
            kk.copy_from_slice(&plain);
        }
        plain.iter_mut().for_each(|b| *b = 0);
        let want = match flags {
            Some(f) => bind_tag_flags(&kk, rp, key, f, uv_key.as_ref().map(|(b, p)| (*b, p))),
            None => bind_tag(&kk, rp, key),
        };
        let ok = plain.len() == 32 && same(&want, tag);
        let f = flags.unwrap_or(0);
        let (resident, protect) = (f & CRED_RESIDENT != 0, 1 + ((f & CRED_PROTECT_MASK) >> CRED_PROTECT_SHIFT));
        let random = hmac(&kk, RANDOM_LABEL);
        let random_uv = hmac(&kk, RANDOM_UV_LABEL);
        kk.fill(0);
        ok.then_some(Cred { key, random, random_uv, resident, protect, sign_bound: f & CRED_SIGN_BOUND != 0, uv_key })
    }

    fn make_credential(&mut self, k: &dyn Keys, body: &[u8], o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut rd = Rd::new(body);
        let Some(Item::Map(n)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
        let (mut cdh, mut rp, mut user, mut es256, mut hmac_secret, mut uv, mut rk) = (None, None, false, false, false, false, false);
        let (mut user_id, mut user_name, mut user_display): (Option<&[u8]>, &[u8], &[u8]) = (None, &[], &[]);
        let (mut pin_auth, mut pin_proto): (Option<&[u8]>, Option<i64>) = (None, None);
        let mut protect: Option<u8> = None;
        let mut exclude: KVec<&[u8]> = KVec::new();
        for _ in 0..n {
            let Some(Item::Int(key)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
            match key {
                1 => match rd.item() {
                    Some(Item::Bytes(b)) if b.len() == 32 => cdh = Some(b),
                    _ => return Err(ERR_INVALID_PARAMETER),
                },
                2 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match (rd.item(), rd.item()) {
                            (Some(Item::Text(b"id")), Some(Item::Text(t))) => rp = Some(t),
                            (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                            (Some(_), Some(_)) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                3 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match (rd.item(), rd.item()) {
                            (Some(Item::Text(b"id")), Some(Item::Bytes(b))) => user_id = Some(b),
                            (Some(Item::Text(b"name")), Some(Item::Text(t))) => user_name = t,
                            (Some(Item::Text(b"displayName")), Some(Item::Text(t))) => user_display = t,
                            (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                            (Some(_), Some(_)) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                    user = true;
                }
                4 => {
                    let Some(Item::Array(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        let Some(Item::Map(f)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                        let (mut alg, mut pk) = (None, false);
                        for _ in 0..f {
                            match (rd.item(), rd.item()) {
                                (Some(Item::Text(b"alg")), Some(Item::Int(a))) => alg = Some(a),
                                (Some(Item::Text(b"type")), Some(Item::Text(t))) => pk = t == b"public-key",
                                (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                                (Some(_), Some(_)) => {}
                                _ => return Err(ERR_INVALID_CBOR),
                            }
                        }
                        es256 |= pk && alg == Some(-7);
                    }
                }
                5 => {
                    let Some(Item::Array(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        let Some(Item::Map(f)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                        for _ in 0..f {
                            match (rd.item(), rd.item()) {
                                (Some(Item::Text(b"id")), Some(Item::Bytes(b))) => {
                                    exclude.push(b, GFP_KERNEL).map_err(|_| ERR_OTHER)?
                                }
                                (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                                (Some(_), Some(_)) => {}
                                _ => return Err(ERR_INVALID_CBOR),
                            }
                        }
                    }
                }
                6 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match rd.item() {
                            Some(Item::Text(b"hmac-secret")) => match rd.item() {
                                Some(Item::Bool(b)) => hmac_secret = b,
                                _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                            },
                            Some(Item::Text(b"credProtect")) => match rd.item() {
                                Some(Item::Int(l @ 1..=3)) => protect = Some(l as u8),
                                _ => return Err(ERR_INVALID_PARAMETER),
                            },
                            Some(_) => rd.skip().ok_or(ERR_INVALID_CBOR)?,
                            None => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                7 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match (rd.item(), rd.item()) {
                            (Some(Item::Text(b"rk")), Some(Item::Bool(b))) => rk = b,
                            (Some(Item::Text(b"uv")), Some(Item::Bool(b))) => uv = b,
                            (Some(Item::Text(_)), Some(Item::Bool(_))) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                8 => match rd.item() {
                    Some(Item::Bytes(b)) => pin_auth = Some(b),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                9 => match rd.item() {
                    Some(Item::Int(p)) => pin_proto = Some(p),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        let cdh = cdh.ok_or(ERR_MISSING_PARAMETER)?;
        let rp = rp.ok_or(ERR_MISSING_PARAMETER)?;
        if !user {
            return Err(ERR_MISSING_PARAMETER);
        }
        if !es256 {
            return Err(ERR_UNSUPPORTED_ALGORITHM);
        }
        let rp_hash = crate::sks::sha256(rp);
        // a resident credential: the store there and readable, the user's handle given, before the user is asked
        if rk {
            if !k.store_ok() {
                return Err(ERR_UNSUPPORTED_OPTION);
            }
            if user_id.is_none_or(|id| id.is_empty() || id.len() > crate::rk::USER_ID_MAX) || rp.len() > crate::rk::RP_MAX {
                return Err(ERR_INVALID_PARAMETER);
            }
            if !self.store.load(k) {
                return Err(ERR_OTHER);
            }
        }
        // a pinUvAuthParam stands for the verification that gave its token, whose touch is the presence once; an empty
        // one asks for a touch to pick an authenticator (and no PIN is set)
        let by_token = match pin_auth {
            Some([]) => {
                k.presence()?;
                return Err(if k.uv_ready() { ERR_PIN_INVALID } else { ERR_PIN_NOT_SET });
            }
            Some(param) => {
                Some(self.token_check(k, pin_proto.ok_or(ERR_MISSING_PARAMETER)?, param, &[cdh], PERM_MC, Some(&rp_hash))?)
            }
            None => None,
        };
        // credProtect 3 while uv_bind(): the credential's own key is bound, and its attestation is signed with the
        // match's ACM context (the token's, or a verification made here)
        let sign_bound = protect == Some(3) && k.uv_bind();
        let mut ctx = UvCtx { k, acm: None };
        match by_token {
            Some(present) => {
                uv = true;
                if sign_bound {
                    ctx.acm = Some(self.token.as_mut().and_then(|t| t.acm.take()).ok_or(ERR_PIN_AUTH_INVALID)?);
                }
                if !present {
                    k.presence()?;
                }
                // the token is spent with the credential it made
                self.token_drop(k);
            }
            None if sign_bound => {
                ctx.acm = Some(k.verify(true)?.ok_or(ERR_OTHER)?);
                uv = true;
            }
            None if uv => {
                k.verify(false)?;
            }
            // a resident credential is made with a verification once the authenticator can make one (CTAP 2.1,
            // makeCredUvNotRqd covers the others)
            None if rk && k.uv_ready() => return Err(ERR_PUAT_REQUIRED),
            None => k.presence()?,
        }
        let listed = exclude.iter().any(|id| id.first() == Some(&CRED_VERSION_FLAGS)) && k.store_ok() && self.store.load(k);
        if exclude.iter().any(|id| Self::open(k, id, &rp_hash).is_some_and(|c| !c.resident || (listed && self.store.has(id)))) {
            return Err(0x19); // CTAP2_ERR_CREDENTIAL_EXCLUDED
        }
        let (blob, public) = if sign_bound { k.key_create_uv(true) } else { k.key_create() }.ok_or(ERR_OTHER)?;
        // made with a user verification: a bound key for hmac-secret's secret after one, and the point of its ECDH,
        // the public half of a key made for it and dropped
        let uv_key = if uv && k.uv_bind() {
            let (bound, _) = k.key_create_uv(false).ok_or(ERR_OTHER)?;
            let (_, peer) = k.key_create().ok_or(ERR_OTHER)?;
            Some((bound, peer))
        } else {
            None
        };
        let mut kk = [0u8; 32];
        k.random(&mut kk);
        let sealed = k.seal(&kk);
        let cred_flags = if rk { CRED_RESIDENT } else { 0 } | ((protect.unwrap_or(1) - 1) << CRED_PROTECT_SHIFT) | if uv_key.is_some() { CRED_UV_KEY } else { 0 } | if sign_bound { CRED_SIGN_BOUND } else { 0 };
        let tag = bind_tag_flags(&kk, &rp_hash, &blob, cred_flags, uv_key.as_ref().map(|(b, p)| (&b[..], p)));
        kk.fill(0);
        let sealed = sealed.ok_or(ERR_OTHER)?;
        let build = || -> Result<(KVec<u8>, KVec<u8>)> {
            let mut id = KVec::new();
            id.push(CRED_VERSION_FLAGS, GFP_KERNEL)?;
            id.push(cred_flags, GFP_KERNEL)?;
            id.extend_from_slice(&(sealed.len() as u16).to_be_bytes(), GFP_KERNEL)?;
            id.extend_from_slice(&sealed, GFP_KERNEL)?;
            id.extend_from_slice(&tag, GFP_KERNEL)?;
            id.extend_from_slice(&(blob.len() as u16).to_be_bytes(), GFP_KERNEL)?;
            id.extend_from_slice(&blob, GFP_KERNEL)?;
            if let Some((bound, peer)) = &uv_key {
                id.extend_from_slice(&(bound.len() as u16).to_be_bytes(), GFP_KERNEL)?;
                id.extend_from_slice(bound, GFP_KERNEL)?;
                id.extend_from_slice(peer, GFP_KERNEL)?;
            }
            let mut ad = Cbor::new();
            ad.raw(&rp_hash)?;
            // UP, AT, UV after a match, and ED with an extension's output; the counter 0 (none kept)
            let ed = hmac_secret || protect.is_some();
            ad.raw(&[0x41 | if uv { FLAG_UV } else { 0 } | if ed { 0x80 } else { 0 }, 0, 0, 0, 0])?;
            ad.raw(&AAGUID)?.raw(&(id.len() as u16).to_be_bytes())?.raw(&id)?;
            cose_p256(&mut ad, -7, &public)?;
            if ed {
                ad.map(usize::from(protect.is_some()) + usize::from(hmac_secret))?;
                if let Some(l) = protect {
                    ad.text(b"credProtect")?.int(i64::from(l))?;
                }
                if hmac_secret {
                    ad.text(b"hmac-secret")?.bool(true)?;
                }
            }
            Ok((id, ad.0))
        };
        let (id, auth_data) = build().map_err(|_| ERR_OTHER)?;
        let mut signed = KVec::new();
        signed.extend_from_slice(&auth_data, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        signed.extend_from_slice(cdh, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        let digest = crate::sks::sha256(&signed);
        let sig = match (sign_bound, &ctx.acm) {
            (true, Some(acm)) => k.key_sign_uv(&blob, &digest, acm).ok_or(ERR_OPERATION_DENIED)?,
            (true, None) => return Err(ERR_OTHER),
            (false, _) => k.key_sign(&blob, &digest).ok_or(ERR_OTHER)?,
        };
        // a resident credential is on the disk before the answer goes
        if rk {
            let r = crate::rk::Resident::new(&rp_hash, rp, user_id.unwrap_or(&[]), user_name, user_display, &id).map_err(|_| ERR_OTHER)?;
            if !self.store.put(r) {
                return Err(ERR_KEY_STORE_FULL);
            }
            if !self.store.save(k) {
                return Err(ERR_OTHER);
            }
        }
        (|| -> Result {
            o.map(3)?.int(1)?.text(b"packed")?.int(2)?.bytes(&auth_data)?;
            o.int(3)?.map(2)?.text(b"alg")?.int(-7)?.text(b"sig")?.bytes(&sig)?;
            Ok(())
        })()
        .map_err(|_| ERR_OTHER)
    }

    fn get_assertion(&mut self, k: &dyn Keys, body: &[u8], o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut rd = Rd::new(body);
        let Some(Item::Map(n)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
        let (mut rp, mut cdh, mut up, mut uv) = (None, None, true, false);
        let mut allow: KVec<&[u8]> = KVec::new();
        let (mut peer, mut salt_enc, mut salt_auth, mut hmac_asked, mut hmac_proto) = (None, None, None, false, 1i64);
        let (mut pin_auth, mut pin_proto): (Option<&[u8]>, Option<i64>) = (None, None);
        for _ in 0..n {
            let Some(Item::Int(key)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
            match key {
                1 => match rd.item() {
                    Some(Item::Text(t)) => rp = Some(t),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                2 => match rd.item() {
                    Some(Item::Bytes(b)) if b.len() == 32 => cdh = Some(b),
                    _ => return Err(ERR_INVALID_PARAMETER),
                },
                3 => {
                    let Some(Item::Array(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        let Some(Item::Map(f)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                        for _ in 0..f {
                            match (rd.item(), rd.item()) {
                                (Some(Item::Text(b"id")), Some(Item::Bytes(b))) => {
                                    allow.push(b, GFP_KERNEL).map_err(|_| ERR_OTHER)?
                                }
                                (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                                (Some(_), Some(_)) => {}
                                _ => return Err(ERR_INVALID_CBOR),
                            }
                        }
                    }
                }
                4 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match rd.item() {
                            Some(Item::Text(b"hmac-secret")) => {
                                hmac_asked = true;
                                let Some(Item::Map(h)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                                for _ in 0..h {
                                    match rd.item() {
                                        Some(Item::Int(1)) => peer = Some(cose_point(&mut rd).ok_or(ERR_INVALID_PARAMETER)?),
                                        Some(Item::Int(2)) => match rd.item() {
                                            Some(Item::Bytes(b)) if matches!(b.len(), 32 | 64 | 48 | 80) => salt_enc = Some(b),
                                            _ => return Err(ERR_INVALID_LENGTH),
                                        },
                                        Some(Item::Int(3)) => match rd.item() {
                                            Some(Item::Bytes(b)) if b.len() == 16 || b.len() == 32 => salt_auth = Some(b),
                                            _ => return Err(ERR_INVALID_LENGTH),
                                        },
                                        Some(Item::Int(4)) => match rd.item() {
                                            Some(Item::Int(p @ (1 | 2))) => hmac_proto = p,
                                            _ => return Err(ERR_INVALID_PARAMETER),
                                        },
                                        Some(_) => rd.skip().ok_or(ERR_INVALID_CBOR)?,
                                        None => return Err(ERR_INVALID_CBOR),
                                    }
                                }
                            }
                            Some(_) => rd.skip().ok_or(ERR_INVALID_CBOR)?,
                            None => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                5 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match (rd.item(), rd.item()) {
                            (Some(Item::Text(b"rk")), Some(Item::Bool(true))) => return Err(ERR_UNSUPPORTED_OPTION),
                            (Some(Item::Text(b"uv")), Some(Item::Bool(b))) => uv = b,
                            (Some(Item::Text(b"up")), Some(Item::Bool(b))) => up = b,
                            (Some(Item::Text(_)), Some(Item::Bool(_))) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                6 => match rd.item() {
                    Some(Item::Bytes(b)) => pin_auth = Some(b),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                7 => match rd.item() {
                    Some(Item::Int(p)) => pin_proto = Some(p),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        let rp_hash = crate::sks::sha256(rp.ok_or(ERR_MISSING_PARAMETER)?);
        let cdh = cdh.ok_or(ERR_MISSING_PARAMETER)?;
        // as MakeCredential's: the token's HMAC over the client data's hash
        let by_token = match pin_auth {
            Some([]) => {
                k.presence()?;
                return Err(if k.uv_ready() { ERR_PIN_INVALID } else { ERR_PIN_NOT_SET });
            }
            Some(param) => {
                Some(self.token_check(k, pin_proto.ok_or(ERR_MISSING_PARAMETER)?, param, &[cdh], PERM_GA, Some(&rp_hash))?)
            }
            None => None,
        };
        if by_token.is_some() {
            uv = true;
        }
        // the allow list's first credential of ours; with no list the RP's resident credentials, the newest first,
        // the others kept for GetNextAssertion
        let copy = |b: &[u8]| -> core::result::Result<KVec<u8>, u8> {
            let mut v = KVec::new();
            v.extend_from_slice(b, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
            Ok(v)
        };
        let mut first: Option<Found> = None;
        let mut rest: KVec<Found> = KVec::new();
        if allow.is_empty() {
            if k.store_ok() && self.store.load(k) {
                for r in self.store.find(&rp_hash).map_err(|_| ERR_OTHER)?.iter() {
                    // credProtect 2 and 3: no answer without a list unless the user is verified
                    let Some(sign_bound) = Self::open(k, &r.cred_id, &rp_hash).filter(|c| c.protect == 1 || uv).map(|c| c.sign_bound) else {
                        continue;
                    };
                    let f = Found { id: copy(&r.cred_id)?, user: Some((copy(&r.user_id)?, copy(&r.user_name)?, copy(&r.user_display)?)), sign_bound };
                    if first.is_none() {
                        first = Some(f);
                    } else {
                        rest.push(f, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
                    }
                }
            }
        } else {
            // a resident credential named in the list answers only while the store has it (read only when one is)
            // and credProtect 3 only with the user verified
            let listed = allow.iter().any(|id| id.first() == Some(&CRED_VERSION_FLAGS)) && k.store_ok() && self.store.load(k);
            if let Some(id) = allow.iter().find(|id| Self::open(k, id, &rp_hash).is_some_and(|c| (!c.resident || (listed && self.store.has(id))) && (c.protect < 3 || uv))) {
                // a resident one answers with its user's handle here too
                let user = match self.store.get(id).filter(|_| listed) {
                    Some(r) => Some((copy(&r.user_id)?, copy(&r.user_name)?, copy(&r.user_display)?)),
                    None => None,
                };
                first = Some(Found { id: copy(id)?, user, sign_bound: false });
            }
        }
        let mut first = first.ok_or(ERR_NO_CREDENTIALS)?;
        let cred = Self::open(k, &first.id, &rp_hash).ok_or(ERR_NO_CREDENTIALS)?;
        first.sign_bound = cred.sign_bound;
        // a match is presence too: one touch answers both; so is the touch of the verification that gave a token,
        // once, and the token is spent with a presence
        // For hmac-secret after a verification on a credential with a bound key, the SEP's ECDH with that key gives
        // the secret, and only with the ACM context the verification's match went into: the token's, or this match's
        // So do the keys that sign only with it (credProtect 3 while uv_bind()), the other credentials' too
        let bound = if uv && hmac_asked { cred.uv_key } else { None };
        let want_ctx = uv && (bound.is_some() || first.sign_bound || rest.iter().any(|f| f.sign_bound));
        // `ctx` owns a context this request must delete; `acm` is the one it uses (a token that lives on, after a
        // request without presence, keeps its own)
        let mut ctx = UvCtx { k, acm: None };
        let mut acm: Option<[u8; 16]> = None;
        match by_token {
            Some(present) => {
                if want_ctx {
                    acm = Some(self.token.as_ref().and_then(|t| t.acm).ok_or(ERR_PIN_AUTH_INVALID)?);
                }
                if up {
                    if !present {
                        k.presence()?;
                    }
                    ctx.acm = self.token.as_mut().and_then(|t| t.acm.take());
                    self.token_drop(k);
                }
            }
            None if uv && want_ctx => {
                ctx.acm = Some(k.verify(true)?.ok_or(ERR_OTHER)?);
                acm = ctx.acm;
            }
            None if uv => {
                k.verify(false)?;
            }
            None if up => k.presence()?,
            None => {}
        }
        let mut z_uv: Option<[u8; 32]> = None;
        if let (Some((blob, peer)), Some(acm)) = (&bound, &acm) {
            z_uv = Some(k.key_ecdh_uv(blob, peer, acm).ok_or(ERR_OPERATION_DENIED)?);
        }
        // hmac-secret (PIN/UV protocol 1): the shared secret SHA-256(ECDH's X); the salts' MAC checked, the salts
        // decrypted, each HMACed under CredRandom, the outputs encrypted back
        let mut output = KVec::new();
        if hmac_asked {
            let (peer, salt_enc, salt_auth) = match (peer, salt_enc, salt_auth) {
                (Some(p), Some(e), Some(a)) => (p, e, a),
                _ => return Err(ERR_MISSING_PARAMETER),
            };
            let (ka, _) = self.ka.as_ref().ok_or(ERR_PIN_AUTH_INVALID)?;
            let mut z = k.key_ecdh(ka, &peer).ok_or(ERR_INVALID_PARAMETER)?;
            let shared = Shared::new(hmac_proto, &z);
            z.fill(0);
            let shared = shared.ok_or(ERR_INVALID_PARAMETER)?;
            if !shared.verify(salt_enc, salt_auth) {
                return Err(ERR_PIN_AUTH_INVALID);
            }
            // one salt or two, 32 bytes each
            let mut salts = shared.decrypt(salt_enc).ok_or(ERR_INVALID_LENGTH)?;
            if salts.len() != 32 && salts.len() != 64 {
                salts.iter_mut().for_each(|b| *b = 0);
                return Err(ERR_INVALID_LENGTH);
            }
            let mut cred_random = match (&z_uv, uv) {
                (Some(z), _) => hmac(&cred.random_uv, z),
                (None, true) => cred.random_uv,
                (None, false) => cred.random,
            };
            let mut out = [0u8; 64];
            for (i, salt) in salts.chunks(32).enumerate() {
                out[i * 32..i * 32 + 32].copy_from_slice(&hmac(&cred_random, salt));
            }
            cred_random.fill(0);
            if let Some(z) = z_uv.as_mut() {
                z.fill(0);
            }
            let enc = shared.encrypt(k, &out[..salts.len()]);
            salts.iter_mut().for_each(|b| *b = 0);
            out.fill(0);
            output = enc.ok_or(ERR_OTHER)?;
        }
        // UP: the presence asked for, or a match made here; a token's verification is not this request's presence
        let flags = u8::from(up || (uv && by_token.is_none())) | if uv { FLAG_UV } else { 0 } | if hmac_asked { 0x80 } else { 0 };
        let ext = hmac_asked.then_some(&output[..]);
        // the user's names go out only after a verification, and only with several credentials to choose from: with
        // one, the handle alone tells the platform that there is nothing to choose (Chromium waits for its account
        // picker otherwise)
        let names = uv && !rest.is_empty();
        Self::assertion(k, &first, cred.key, &rp_hash, cdh, flags, ext, names, 1 + rest.len(), acm.as_ref(), o)?;
        if !rest.is_empty() {
            let mut c = [0u8; 32];
            c.copy_from_slice(cdh);
            // the others answer with the same flags and no extension's output, their bound keys with the same context
            let own = ctx.acm.take().is_some();
            self.next = Some(Next { rp_hash, cdh: c, flags: flags & !0x80, names, rest, at: 0, since: k.now_s(), acm, own, cid: self.walk_cid });
        }
        Ok(())
    }

    /// One assertion's answer: the authenticator data (the RP ID's hash, the flags, the counter 0, `ext`'s
    /// hmac-secret output), its signature with the client data's hash by the credential's key, the credential, a
    /// resident one's user (the handle; with `names` its names too) and, on the first of several,
    /// their number.
    #[allow(clippy::too_many_arguments)]
    fn assertion(k: &dyn Keys, found: &Found, key: &[u8], rp_hash: &[u8; 32], cdh: &[u8], flags: u8, ext: Option<&[u8]>, names: bool, count: usize, acm: Option<&[u8; 16]>, o: &mut Cbor) -> core::result::Result<(), u8> {
        let build = || -> Result<KVec<u8>> {
            let mut ad = Cbor::new();
            ad.raw(rp_hash)?;
            ad.raw(&[flags, 0, 0, 0, 0])?;
            if let Some(output) = ext {
                ad.map(1)?.text(b"hmac-secret")?.bytes(output)?;
            }
            Ok(ad.0)
        };
        let auth_data = build().map_err(|_| ERR_OTHER)?;
        let mut signed = KVec::new();
        signed.extend_from_slice(&auth_data, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        signed.extend_from_slice(cdh, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        let digest = crate::sks::sha256(&signed);
        let sig = match (found.sign_bound, acm) {
            (true, Some(acm)) => k.key_sign_uv(key, &digest, acm).ok_or(ERR_OPERATION_DENIED)?,
            (true, None) => return Err(ERR_OPERATION_DENIED),
            (false, _) => k.key_sign(key, &digest).ok_or(ERR_OTHER)?,
        };
        (|| -> Result {
            o.map(3 + usize::from(found.user.is_some()) + usize::from(count > 1))?;
            o.int(1)?.map(2)?.text(b"id")?.bytes(&found.id)?.text(b"type")?.text(b"public-key")?;
            o.int(2)?.bytes(&auth_data)?.int(3)?.bytes(&sig)?;
            if let Some((id, name, display)) = &found.user {
                let (with_name, with_display) = (names && !name.is_empty(), names && !display.is_empty());
                o.int(4)?.map(1 + usize::from(with_name) + usize::from(with_display))?.text(b"id")?.bytes(id)?;
                if with_name {
                    o.text(b"name")?.text(name)?;
                }
                if with_display {
                    o.text(b"displayName")?.text(display)?;
                }
            }
            if count > 1 {
                o.int(5)?.int(count as i64)?;
            }
            Ok(())
        })()
        .map_err(|_| ERR_OTHER)
    }

    /// GetNextAssertion: the next of the last GetAssertion's credentials, within 30 s of it and of each other.
    fn next_assertion(&mut self, k: &dyn Keys, o: &mut Cbor) -> core::result::Result<(), u8> {
        let now = k.now_s();
        let Some(n) = self.next.as_mut() else { return Err(ERR_NOT_ALLOWED) };
        if now.saturating_sub(n.since) > 30 || n.at >= n.rest.len() {
            self.next_drop(k);
            return Err(ERR_NOT_ALLOWED);
        }
        let found = &n.rest[n.at];
        let cred = Self::open(k, &found.id, &n.rp_hash).ok_or(ERR_NOT_ALLOWED)?;
        Self::assertion(k, found, cred.key, &n.rp_hash, &n.cdh, n.flags, None, n.names, 1, n.acm.as_ref(), o)?;
        n.at += 1;
        n.since = now;
        if n.at >= n.rest.len() {
            self.next_drop(k);
        }
        Ok(())
    }

    /// Reset: after a touch, every resident credential dropped (a credential's ID without one stays valid: its key
    /// is in it).
    fn reset(&mut self, k: &dyn Keys, age: u64) -> core::result::Result<(), u8> {
        // CTAP 2.1: only within 10 s of the authenticator's start. A touch does not say what it approves, and a
        // request left waiting would take the next one. One credential goes by credential management; all go with
        // the store's files.
        if age > RESET_S {
            return Err(ERR_NOT_ALLOWED);
        }
        k.presence()?;
        self.token_drop(k);
        if k.store_ok() && !self.store.clear(k) {
            return Err(ERR_OTHER);
        }
        Ok(())
    }

    /// Credential management (CTAP 2.1): the resident credentials counted, listed by RP, deleted and renamed, each
    /// request but a GetNext proved by the token's HMAC over its subcommand byte and its parameters' CBOR, with the
    /// cm permission. A token for one RP serves that RP only.
    fn cred_mgmt(&mut self, k: &dyn Keys, body: &[u8], o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut rd = Rd::new(body);
        let Some(Item::Map(n)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
        let (mut sub, mut params, mut proto, mut param): (Option<i64>, &[u8], Option<i64>, Option<&[u8]>) = (None, &[], None, None);
        let (mut rp_hash, mut cred_id, mut user_id): (Option<&[u8]>, Option<&[u8]>, Option<&[u8]>) = (None, None, None);
        let (mut user_name, mut user_display): (&[u8], &[u8]) = (&[], &[]);
        for _ in 0..n {
            let Some(Item::Int(key)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
            match key {
                1 => match rd.item() {
                    Some(Item::Int(s)) => sub = Some(s),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                2 => {
                    // the parameters' own bytes are what the token signs
                    let from = rd.at;
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        let Some(Item::Int(pk)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
                        match pk {
                            1 => match rd.item() {
                                Some(Item::Bytes(b)) if b.len() == 32 => rp_hash = Some(b),
                                _ => return Err(ERR_INVALID_PARAMETER),
                            },
                            2 => {
                                let Some(Item::Map(f)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                                for _ in 0..f {
                                    match (rd.item(), rd.item()) {
                                        (Some(Item::Text(b"id")), Some(Item::Bytes(b))) => cred_id = Some(b),
                                        (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                                        (Some(_), Some(_)) => {}
                                        _ => return Err(ERR_INVALID_CBOR),
                                    }
                                }
                            }
                            3 => {
                                let Some(Item::Map(f)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                                for _ in 0..f {
                                    match (rd.item(), rd.item()) {
                                        (Some(Item::Text(b"id")), Some(Item::Bytes(b))) => user_id = Some(b),
                                        (Some(Item::Text(b"name")), Some(Item::Text(t))) => user_name = t,
                                        (Some(Item::Text(b"displayName")), Some(Item::Text(t))) => user_display = t,
                                        (Some(_), Some(nested @ (Item::Array(_) | Item::Map(_)))) => rd.skip_rest(&nested).ok_or(ERR_INVALID_CBOR)?,
                                        (Some(_), Some(_)) => {}
                                        _ => return Err(ERR_INVALID_CBOR),
                                    }
                                }
                            }
                            _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
                        }
                    }
                    params = &body[from..rd.at];
                }
                3 => match rd.item() {
                    Some(Item::Int(p)) => proto = Some(p),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                4 => match rd.item() {
                    Some(Item::Bytes(b)) => param = Some(b),
                    _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
                },
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        let sub = sub.ok_or(ERR_MISSING_PARAMETER)?;
        if !k.store_ok() {
            return Err(ERR_INVALID_COMMAND);
        }
        // the two GetNexts answer from the enumeration under way, with no proof of their own
        if sub == 3 || sub == 5 {
            return self.walk_next(sub == 3, o);
        }
        if !(1..=7).contains(&sub) {
            return Err(ERR_INVALID_PARAMETER);
        }
        let param = param.ok_or(ERR_PUAT_REQUIRED)?;
        self.walk = None;
        let _ = self.token_check(k, proto.ok_or(ERR_MISSING_PARAMETER)?, param, &[&[sub as u8], params], PERM_CM, None)?;
        if !self.store.load(k) {
            return Err(ERR_OTHER);
        }
        // a token for one RP: only that RP's credentials
        let only = self.token.as_ref().and_then(|t| t.rp);
        let allowed = |h: &[u8; 32]| only.is_none_or(|o| &o == h);
        let copy = |b: &[u8]| -> core::result::Result<KVec<u8>, u8> {
            let mut v = KVec::new();
            v.extend_from_slice(b, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
            Ok(v)
        };
        match sub {
            // getCredsMetadata
            1 => {
                if only.is_some() {
                    return Err(ERR_PIN_AUTH_INVALID);
                }
                let n = self.store.all().len();
                (|| -> Result { o.map(2)?.int(1)?.int(n as i64)?.int(2)?.int((crate::rk::MAX_ENTRIES - n) as i64)?; Ok(()) })().map_err(|_| ERR_OTHER)
            }
            // enumerateRPsBegin
            2 => {
                if only.is_some() {
                    return Err(ERR_PIN_AUTH_INVALID);
                }
                let mut rps: KVec<(KVec<u8>, [u8; 32])> = KVec::new();
                for r in self.store.all() {
                    if !rps.iter().any(|(_, h)| h == &r.rp_hash) {
                        rps.push((copy(&r.rp_id)?, r.rp_hash), GFP_KERNEL).map_err(|_| ERR_OTHER)?;
                    }
                }
                if rps.is_empty() {
                    return Err(ERR_NO_CREDENTIALS);
                }
                self.walk = Some(Walk::Rps(rps, 0));
                self.walk_next(true, o)
            }
            // enumerateCredentialsBegin
            4 => {
                let h: [u8; 32] = rp_hash.ok_or(ERR_MISSING_PARAMETER)?.try_into().map_err(|_| ERR_INVALID_PARAMETER)?;
                if !allowed(&h) {
                    return Err(ERR_PIN_AUTH_INVALID);
                }
                let mut creds: KVec<Listed> = KVec::new();
                for r in self.store.find(&h).map_err(|_| ERR_OTHER)?.iter() {
                    let Some((public, protect)) = Self::open(k, &r.cred_id, &h).and_then(|c| Some((k.key_public(c.key)?, c.protect))) else { continue };
                    let user = (copy(&r.user_id)?, copy(&r.user_name)?, copy(&r.user_display)?);
                    creds.push(Listed { id: copy(&r.cred_id)?, user, public, protect }, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
                }
                if creds.is_empty() {
                    return Err(ERR_NO_CREDENTIALS);
                }
                self.walk = Some(Walk::Creds(creds, 0));
                self.walk_next(false, o)
            }
            // deleteCredential, updateUserInformation: saved before the answer
            6 | 7 => {
                let id = cred_id.ok_or(ERR_MISSING_PARAMETER)?;
                let Some(h) = self.store.all().iter().find(|r| r.cred_id[..] == *id).map(|r| r.rp_hash) else {
                    return Err(ERR_NO_CREDENTIALS);
                };
                if !allowed(&h) {
                    return Err(ERR_PIN_AUTH_INVALID);
                }
                let changed = if sub == 6 {
                    self.store.remove(id)
                } else {
                    self.store.rename(id, user_id.ok_or(ERR_MISSING_PARAMETER)?, user_name, user_display).map_err(|_| ERR_OTHER)?
                };
                if !changed {
                    // the credential is there: the handle is not its user's
                    return Err(if sub == 6 { ERR_NO_CREDENTIALS } else { ERR_INVALID_PARAMETER });
                }
                // a delete goes to both files: the older one would bring the credential back if the newer were lost
                if !self.store.save(k) || (sub == 6 && !self.store.save(k)) {
                    return Err(ERR_OTHER);
                }
                Ok(())
            }
            _ => Err(ERR_INVALID_PARAMETER),
        }
    }

    /// The enumeration's next RP (its ID and hash, and on the first their number) or credential (its user, ID and
    /// public key, its credProtect level, and on the first their number).
    fn walk_next(&mut self, rps: bool, o: &mut Cbor) -> core::result::Result<(), u8> {
        let r = match (self.walk.as_mut(), rps) {
            (Some(Walk::Rps(list, at)), true) if *at < list.len() => {
                let (id, hash) = &list[*at];
                let total = list.len();
                let first = *at == 0;
                *at += 1;
                (|| -> Result {
                    o.map(2 + usize::from(first))?.int(3)?.map(1)?.text(b"id")?.text(id)?.int(4)?.bytes(hash)?;
                    if first {
                        o.int(5)?.int(total as i64)?;
                    }
                    Ok(())
                })()
            }
            (Some(Walk::Creds(list, at)), false) if *at < list.len() => {
                let c = &list[*at];
                let total = list.len();
                let first = *at == 0;
                *at += 1;
                (|| -> Result {
                    let (name, display) = (!c.user.1.is_empty(), !c.user.2.is_empty());
                    o.map(4 + usize::from(first))?;
                    o.int(6)?.map(1 + usize::from(name) + usize::from(display))?.text(b"id")?.bytes(&c.user.0)?;
                    if name {
                        o.text(b"name")?.text(&c.user.1)?;
                    }
                    if display {
                        o.text(b"displayName")?.text(&c.user.2)?;
                    }
                    o.int(7)?.map(2)?.text(b"id")?.bytes(&c.id)?.text(b"type")?.text(b"public-key")?;
                    o.int(8)?;
                    cose_p256(o, -7, &c.public)?;
                    if first {
                        o.int(9)?.int(total as i64)?;
                    }
                    o.int(10)?.int(i64::from(c.protect))?;
                    Ok(())
                })()
            }
            _ => {
                self.walk = None;
                return Err(ERR_NOT_ALLOWED);
            }
        };
        r.map_err(|_| ERR_OTHER)
    }

    /// The driver going: the token and GetNextAssertion's state with their ACM contexts, and the store's key.
    pub(crate) fn forget(&mut self, k: &dyn Keys) {
        self.token_drop(k);
        self.next_drop(k);
        self.store.forget();
    }
}
