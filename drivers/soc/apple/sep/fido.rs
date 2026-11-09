// SPDX-License-Identifier: GPL-2.0-only

//! The SEP's FIDO2 authenticator (`apple_sep.fido`, docs/hardware/SEP-KEYS.md): CTAP 2.0 over CTAPHID on a virtual
//! HID device (fido.c), for libfido2 and so `systemd-cryptenroll --fido2-device` and the initramfs's LUKS unlock. Stateless:
//! a credential's ID carries its SEP ref key (the private half never leaves the SEP) and a 32-byte key K sealed by
//! kc_wrap (which takes 32 bytes: 96 answered -1, build 64), so only this Mac's key store opens it; an HMAC under K
//! binds the RP ID's hash and the ref key to it, and CredRandom is an HMAC under K. GetInfo, MakeCredential
//! (packed self attestation), GetAssertion with `hmac-secret`, ClientPIN's getKeyAgreement (PIN/UV protocol 1); no
//! resident keys, no PIN, no UV. User presence is a touch on the Touch ID sensor.

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

    fn skip_depth(&mut self, depth: u32) -> Option<()> {
        if depth > 8 {
            return None;
        }
        match self.item()? {
            Item::Array(n) => (0..n).try_for_each(|_| self.skip_depth(depth + 1)),
            Item::Map(n) => (0..n * 2).try_for_each(|_| self.skip_depth(depth + 1)),
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
pub(crate) const ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
pub(crate) const ERR_NO_CREDENTIALS: u8 = 0x2e;
pub(crate) const ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub(crate) const ERR_PIN_NOT_SET: u8 = 0x35;
pub(crate) const ERR_OTHER: u8 = 0x7f;

const CMD_PING: u8 = 0x81;
const CMD_INIT: u8 = 0x86;
const CMD_CBOR: u8 = 0x90;
const CMD_CANCEL: u8 = 0x91;
const CMD_ERROR: u8 = 0xbf;
const BROADCAST: u32 = 0xffff_ffff;
/// The largest message taken (GetInfo's maxMsgSize); CTAPHID's own limit is 7609.
pub(crate) const MAX_MSG: usize = 1200;

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
            return Msg::None;
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
    /// Whether the user is present: a touch on the Touch ID sensor.
    fn presence(&self) -> bool;
    fn random(&self, buf: &mut [u8]);
}

/// The authenticator: CTAPHID's state and the key agreement key of ClientPIN (a ref key made at the first use).
pub(crate) struct Auth {
    pub(crate) hid: Hid,
    ka: Option<(KVec<u8>, [u8; 65])>,
}

/// An opened credential: its ref key and CredRandom.
struct Cred<'a> {
    key: &'a [u8],
    random: [u8; 32],
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

const CRED_VERSION: u8 = 2;
const TAG_LABEL: &[u8] = b"apple-sep-fido bind";
const RANDOM_LABEL: &[u8] = b"apple-sep-fido hmac-secret";

/// The credential's binding: HMAC-SHA-256 under K of the label, the RP ID's hash and the ref key's SHA-256.
fn bind_tag(key: &[u8; 32], rp: &[u8; 32], blob: &[u8]) -> [u8; 32] {
    let mut m = [0u8; 19 + 64];
    m[..19].copy_from_slice(TAG_LABEL);
    m[19..51].copy_from_slice(rp);
    m[51..].copy_from_slice(&crate::sks::sha256(blob));
    hmac(key, &m)
}

impl Auth {
    pub(crate) fn new() -> Self {
        Auth { hid: Hid::new(), ka: None }
    }

    /// A CTAP2 request (command byte, CBOR): the status byte, then the CBOR reply.
    pub(crate) fn request(&mut self, k: &dyn Keys, req: &[u8]) -> KVec<u8> {
        let (cmd, body) = match req.split_first() {
            Some((c, b)) => (*c, b),
            None => (0, &[][..]),
        };
        let mut out = Cbor::new();
        let status = match cmd {
            0x04 => self.get_info(&mut out),
            0x01 => self.make_credential(k, body, &mut out),
            0x02 => self.get_assertion(k, body, &mut out),
            0x06 => self.client_pin(k, body, &mut out),
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

    fn get_info(&self, o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut r = || -> Result {
            o.map(6)?;
            o.int(1)?.array(1)?.text(b"FIDO_2_0")?;
            o.int(2)?.array(1)?.text(b"hmac-secret")?;
            o.int(3)?.bytes(&AAGUID)?;
            o.int(4)?.map(4)?;
            o.text(b"rk")?.bool(false)?.text(b"up")?.bool(true)?;
            o.text(b"plat")?.bool(false)?.text(b"clientPin")?.bool(false)?;
            o.int(5)?.int(MAX_MSG as i64)?;
            o.int(6)?.array(1)?.int(1)?;
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
        let (mut proto, mut sub) = (None, None);
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
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        if proto.ok_or(ERR_MISSING_PARAMETER)? != 1 {
            return Err(ERR_INVALID_PARAMETER);
        }
        match sub.ok_or(ERR_MISSING_PARAMETER)? {
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
            _ => Err(ERR_PIN_NOT_SET),
        }
    }

    /// A credential ID of ours for `rp` (its SHA-256), opened: version 2, u16 the sealed K's length, the sealed K,
    /// the 32-byte binding tag (bind_tag), u16 the key blob's length, the key blob.
    fn open<'a>(k: &dyn Keys, id: &'a [u8], rp: &[u8; 32]) -> Option<Cred<'a>> {
        let (&v, rest) = id.split_first()?;
        if v != CRED_VERSION {
            return None;
        }
        let n = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let sealed = rest.get(2..2 + n)?;
        let tag = rest.get(2 + n..2 + n + 32)?;
        let rest = rest.get(2 + n + 32..)?;
        let m = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let key = rest.get(2..2 + m)?;
        if rest.len() != 2 + m {
            return None;
        }
        let mut plain = k.unseal(sealed)?;
        let mut kk = [0u8; 32];
        if plain.len() == 32 {
            kk.copy_from_slice(&plain);
        }
        plain.iter_mut().for_each(|b| *b = 0);
        let ok = plain.len() == 32 && same(&bind_tag(&kk, rp, key), tag);
        let random = hmac(&kk, RANDOM_LABEL);
        kk.fill(0);
        ok.then_some(Cred { key, random })
    }

    fn make_credential(&mut self, k: &dyn Keys, body: &[u8], o: &mut Cbor) -> core::result::Result<(), u8> {
        let mut rd = Rd::new(body);
        let Some(Item::Map(n)) = rd.item() else { return Err(ERR_INVALID_CBOR) };
        let (mut cdh, mut rp, mut user, mut es256, mut hmac_secret) = (None, None, false, false, false);
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
                            (Some(_), Some(Item::Array(_) | Item::Map(_))) => return Err(ERR_INVALID_CBOR),
                            (Some(_), Some(_)) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                3 => {
                    rd.skip().ok_or(ERR_INVALID_CBOR)?;
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
                                (Some(_), Some(Item::Array(_) | Item::Map(_))) => return Err(ERR_INVALID_CBOR),
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
                                (Some(_), Some(Item::Array(_) | Item::Map(_))) => return Err(ERR_INVALID_CBOR),
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
                            Some(_) => rd.skip().ok_or(ERR_INVALID_CBOR)?,
                            None => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                7 => {
                    let Some(Item::Map(m)) = rd.item() else { return Err(ERR_CBOR_UNEXPECTED_TYPE) };
                    for _ in 0..m {
                        match (rd.item(), rd.item()) {
                            (Some(Item::Text(b"rk" | b"uv")), Some(Item::Bool(true))) => return Err(ERR_UNSUPPORTED_OPTION),
                            (Some(Item::Text(_)), Some(Item::Bool(_))) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                8 => return Err(ERR_PIN_NOT_SET),
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
        if !k.presence() {
            return Err(ERR_OPERATION_DENIED);
        }
        if exclude.iter().any(|id| Self::open(k, id, &rp_hash).is_some()) {
            return Err(0x19); // CTAP2_ERR_CREDENTIAL_EXCLUDED
        }
        let (blob, public) = k.key_create().ok_or(ERR_OTHER)?;
        let mut kk = [0u8; 32];
        k.random(&mut kk);
        let sealed = k.seal(&kk);
        let tag = bind_tag(&kk, &rp_hash, &blob);
        kk.fill(0);
        let sealed = sealed.ok_or(ERR_OTHER)?;
        let build = || -> Result<(KVec<u8>, KVec<u8>)> {
            let mut id = KVec::new();
            id.push(CRED_VERSION, GFP_KERNEL)?;
            id.extend_from_slice(&(sealed.len() as u16).to_be_bytes(), GFP_KERNEL)?;
            id.extend_from_slice(&sealed, GFP_KERNEL)?;
            id.extend_from_slice(&tag, GFP_KERNEL)?;
            id.extend_from_slice(&(blob.len() as u16).to_be_bytes(), GFP_KERNEL)?;
            id.extend_from_slice(&blob, GFP_KERNEL)?;
            let mut ad = Cbor::new();
            ad.raw(&rp_hash)?;
            // UP, AT, and ED when hmac-secret was asked for; the counter 0 (none kept)
            ad.raw(&[0x41 | if hmac_secret { 0x80 } else { 0 }, 0, 0, 0, 0])?;
            ad.raw(&AAGUID)?.raw(&(id.len() as u16).to_be_bytes())?.raw(&id)?;
            cose_p256(&mut ad, -7, &public)?;
            if hmac_secret {
                ad.map(1)?.text(b"hmac-secret")?.bool(true)?;
            }
            Ok((id, ad.0))
        };
        let (_, auth_data) = build().map_err(|_| ERR_OTHER)?;
        let mut signed = KVec::new();
        signed.extend_from_slice(&auth_data, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        signed.extend_from_slice(cdh, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        let sig = k.key_sign(&blob, &crate::sks::sha256(&signed)).ok_or(ERR_OTHER)?;
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
        let (mut rp, mut cdh, mut up) = (None, None, true);
        let mut allow: KVec<&[u8]> = KVec::new();
        let (mut peer, mut salt_enc, mut salt_auth, mut hmac_asked) = (None, None, None, false);
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
                                (Some(_), Some(Item::Array(_) | Item::Map(_))) => return Err(ERR_INVALID_CBOR),
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
                                            Some(Item::Bytes(b)) if b.len() == 32 || b.len() == 64 => salt_enc = Some(b),
                                            _ => return Err(ERR_INVALID_LENGTH),
                                        },
                                        Some(Item::Int(3)) => match rd.item() {
                                            Some(Item::Bytes(b)) if b.len() == 16 => salt_auth = Some(b),
                                            _ => return Err(ERR_INVALID_LENGTH),
                                        },
                                        Some(Item::Int(4)) => match rd.item() {
                                            Some(Item::Int(1)) => {}
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
                            (Some(Item::Text(b"uv" | b"rk")), Some(Item::Bool(true))) => return Err(ERR_UNSUPPORTED_OPTION),
                            (Some(Item::Text(b"up")), Some(Item::Bool(b))) => up = b,
                            (Some(Item::Text(_)), Some(Item::Bool(_))) => {}
                            _ => return Err(ERR_INVALID_CBOR),
                        }
                    }
                }
                6 => return Err(ERR_PIN_NOT_SET),
                _ => rd.skip().ok_or(ERR_INVALID_CBOR)?,
            }
        }
        let rp_hash = crate::sks::sha256(rp.ok_or(ERR_MISSING_PARAMETER)?);
        let cdh = cdh.ok_or(ERR_MISSING_PARAMETER)?;
        let (id, cred) = allow.iter().find_map(|id| Self::open(k, *id, &rp_hash).map(|c| (*id, c))).ok_or(ERR_NO_CREDENTIALS)?;
        if up && !k.presence() {
            return Err(ERR_OPERATION_DENIED);
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
            let mut shared = crate::sks::sha256(&z);
            z.fill(0);
            if !same(&hmac(&shared, salt_enc)[..16], salt_auth) {
                shared.fill(0);
                return Err(ERR_PIN_AUTH_INVALID);
            }
            let mut salts = [0u8; 64];
            let s = &mut salts[..salt_enc.len()];
            s.copy_from_slice(salt_enc);
            if !aes_cbc(&shared, false, s) {
                shared.fill(0);
                return Err(ERR_OTHER);
            }
            let mut out = [0u8; 64];
            for (i, salt) in s.chunks(32).enumerate() {
                out[i * 32..i * 32 + 32].copy_from_slice(&hmac(&cred.random, salt));
            }
            let o2 = &mut out[..salt_enc.len()];
            let enc = aes_cbc(&shared, true, o2);
            salts.fill(0);
            shared.fill(0);
            if !enc || output.extend_from_slice(o2, GFP_KERNEL).is_err() {
                return Err(ERR_OTHER);
            }
        }
        let build = || -> Result<KVec<u8>> {
            let mut ad = Cbor::new();
            ad.raw(&rp_hash)?;
            let flags = u8::from(up) | if hmac_asked { 0x80 } else { 0 };
            ad.raw(&[flags, 0, 0, 0, 0])?;
            if hmac_asked {
                ad.map(1)?.text(b"hmac-secret")?.bytes(&output)?;
            }
            Ok(ad.0)
        };
        let auth_data = build().map_err(|_| ERR_OTHER)?;
        let mut signed = KVec::new();
        signed.extend_from_slice(&auth_data, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        signed.extend_from_slice(cdh, GFP_KERNEL).map_err(|_| ERR_OTHER)?;
        let sig = k.key_sign(cred.key, &crate::sks::sha256(&signed)).ok_or(ERR_OTHER)?;
        (|| -> Result {
            o.map(3)?.int(1)?.map(2)?.text(b"id")?.bytes(id)?.text(b"type")?.text(b"public-key")?;
            o.int(2)?.bytes(&auth_data)?.int(3)?.bytes(&sig)?;
            Ok(())
        })()
        .map_err(|_| ERR_OTHER)
    }
}
