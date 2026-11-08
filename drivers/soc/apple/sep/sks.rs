// SPDX-License-Identifier: GPL-2.0-only
//
// The key store's endpoint 0x12 (`sks `) as macOS 14.8.3's AppleSEPKeyStore drives it (rda AppleSEPKeyStore;
// work/scratch/agents/sks.md), cut to what Touch ID step 6 sends: the fixed start-up of
// AppleKeyStore::init_sep_endpoint 0xfffffe0009ce6724 and effaceable_init, get_capabilities (0x4d), set_env (0x2a)
// and null_d_key (0x0a).
//
// The word (sep_deliver_msg_gated 0xfffffe0009ce4cb4, sep_action 0xfffffe0009ce65c4): byte 0 the endpoint, byte 1
// the command (bit 7 set on the reply), byte 2 a sequence number the reply echoes, byte 3 the reply's status (a
// signed byte), bytes 4-5 the reply's call flags, bytes 6-7 the image's length. The request image goes at 0 of the
// host-to-SEP buffer (ops 0x04/0x02), the reply's at 0 of the SEP-to-host one (0x05/0x03).
//
// The image (ipc.c): a u32 header length and the header (__ipc_header 0xfffffe0009d0d504: always 0x50 on a request;
// a reply's is copied up to 0x50 bytes and its length padded to 4 skipped), then on a v2 reply with flags bit 1 an
// extended header (a blob, __ipc_msg_process_extended_header 0xfffffe0009d0d2a4), then the body: u32 words, u64
// lwords and blobs (a u32 length and the bytes padded to 4), little-endian, unaligned (__word 0xfffffe0009d0cc88,
// __lword 0xfffffe0009d0ce68, __blob 0xfffffe0009d0cce0). The header (gen_ipc_header 0xfffffe0009d0d010):
//   0x00 the digest, 16 bytes        0x10 u32 version (1, or the negotiated 2)
//   0x14 u64 the time in us          0x1c u32 flags (bit 0 encrypted, bit 1 an extended header follows)
//   0x20 u64 0                       0x28 u64 the caller's proc_uniqueid
//   0x30 u32 a credential word       0x34 20 bytes the caller's cdhash
//   0x48 u64 v2 only: calendar seconds
// The digest (__payload_hash 0xfffffe0009d0da88) is SHA-256, truncated to 16 bytes, over the header's 0x10..0x28 and
// 0x28..0x48 (v1) or 0x28..0x50 (v2), then everything after the header (__ipc_msg_protect 0xfffffe0009d0d978:
// from 0x54 on a request, from the parsed header's end on a reply). The kernel's own requests name no process here:
// the uniqueid and the credential word stay 0, and the cdhash is the SHA-1 of the 8-byte uniqueid, as
// gen_ipc_header fills it when get_platform_cdhash 0xfffffe0009d0d174 finds no process (sks.md, step 6's guess).

use kernel::bindings;
use kernel::prelude::*;
use kernel::soc::apple::mailbox::Message;

use crate::proto::EP_SKS;

pub(crate) const CMD_NULL_D_KEY: u8 = 0x0a;
pub(crate) const CMD_SET_ENV: u8 = 0x2a;
pub(crate) const CMD_GET_CAPABILITIES: u8 = 0x4d;
// Stage 7, the identity key bag as macOS 27.2's AppleKeyStore::identity_create, identity_open and identity_load make
// it and AppleKeyStoreUserClient's session unlock opens it (rda AppleSEPKeyStore_272; 27.0.1's is the same).
pub(crate) const CMD_CREATE_KEYBAG: u8 = 0x01;
pub(crate) const CMD_COPY_KEYBAG: u8 = 0x02;
pub(crate) const CMD_LOAD_KEYBAG: u8 = 0x03;
pub(crate) const CMD_UNLOAD_KEYBAG: u8 = 0x05;
pub(crate) const CMD_COPY_KEYBAG_UUID: u8 = 0x06;
pub(crate) const CMD_MAKE_SYSTEM_KEYBAG: u8 = 0x0d;
pub(crate) const CMD_DEVICE_STATE_TRANSITION: u8 = 0x18;
pub(crate) const CMD_GET_DEVICE_STATE: u8 = 0x19;
// Stage 10, the enrolment's credential: the bag's secret verified into an ACM context.
pub(crate) const CMD_VERIFY_SECRET: u8 = 0x21;
pub(crate) const REPLY_BIT: u8 = 0x80;

/// Set at probe for stage 7: only then may the identity's eight commands go to endpoint 0x12 (request_allowed).
pub(crate) static IDENTITY_ARMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(crate) fn cmd_name(cmd: u8) -> &'static str {
    match cmd {
        CMD_NULL_D_KEY => "null_d_key",
        CMD_SET_ENV => "set_env",
        CMD_GET_CAPABILITIES => "get_capabilities",
        CMD_CREATE_KEYBAG => "create_keybag",
        CMD_COPY_KEYBAG => "copy_keybag",
        CMD_LOAD_KEYBAG => "load_keybag",
        CMD_UNLOAD_KEYBAG => "unload_keybag",
        CMD_COPY_KEYBAG_UUID => "copy_keybag_uuid",
        CMD_MAKE_SYSTEM_KEYBAG => "make_system_keybag",
        CMD_DEVICE_STATE_TRANSITION => "device_state_transition",
        CMD_GET_DEVICE_STATE => "get_device_state",
        CMD_VERIFY_SECRET => "verify_secret",
        _ => "?",
    }
}

/// A request's header length (the image's first u32) and where its body starts (__ipc_header_size
/// 0xfffffe0009d0d1d8).
const HEADER_LEN: usize = 0x50;
const BODY_OFF: usize = 4 + HEADER_LEN;
pub(crate) const DIGEST_LEN: usize = 16;
/// The buffers macOS registered each way (sep-1.log 2143, 2166); a longer reply is refused, as macOS refuses it.
pub(crate) const BUF_LEN: usize = 0x8000;

/// macOS 14.8.3's wait for a reply: getAdjustedTimeout(0x1770) with the multiplier 1 (sep_wait_for_reply
/// 0xfffffe0009ce6978).
pub(crate) const TIMEOUT_MS: u32 = 6000;

/// The highest header version the host speaks (init_sep_endpoint: "ours:v2").
pub(crate) const OUR_VERSION: u32 = 2;

/// set_env's environment: u32 1, the ADT's /defaults/cpx-encryption-mode, u32 4 (6 from set_env(true), a user
/// client's), then 0x400 zero bytes (AppleKeyStore::set_env 0xfffffe0009cea680: bzero of 0x3f8 bytes after a zeroed
/// u64).
pub(crate) const SET_ENV_LEN: usize = 0x40c;

pub(crate) const fn request_word(cmd: u8, seq: u8, len: u16) -> u64 {
    (EP_SKS as u64) | ((cmd as u64) << 8) | ((seq as u64) << 16) | ((len as u64) << 48)
}

// macOS 14.8.3's start-up words, bit for bit (sep-1.log 2184, 2193, 2221)
static_assert!(request_word(CMD_GET_CAPABILITIES, 1, 0x64) == 0x0064_0000_0001_4d12);
static_assert!(request_word(CMD_SET_ENV, 2, 0x470) == 0x0470_0000_0002_2a12);
static_assert!(request_word(CMD_NULL_D_KEY, 3, 0x60) == 0x0060_0000_0003_0a12);

/// A word's fields.
#[derive(Clone, Copy)]
pub(crate) struct Word {
    pub(crate) cmd: u8,
    pub(crate) seq: u8,
    pub(crate) status: i8,
    pub(crate) flags: u16,
    pub(crate) len: u16,
}

pub(crate) const fn decode_word(w: u64) -> Word {
    Word {
        cmd: (w >> 8) as u8,
        seq: (w >> 16) as u8,
        status: (w >> 24) as u8 as i8,
        flags: (w >> 32) as u16,
        len: (w >> 48) as u16,
    }
}

// macOS 14.8.3's replies (sep-1.log 2188, 2197, 2225): status 0, flags 1, 0x5c; status 0, 0x58; status -1, nothing.
static_assert!(decode_word(0x005c_0001_0001_cd12).cmd == CMD_GET_CAPABILITIES | REPLY_BIT);
static_assert!(
    decode_word(0x005c_0001_0001_cd12).flags == 1 && decode_word(0x005c_0001_0001_cd12).len == 0x5c
);
static_assert!(
    decode_word(0x0058_0000_0002_aa12).seq == 2 && decode_word(0x0058_0000_0002_aa12).len == 0x58
);
static_assert!(
    decode_word(0x0000_0000_ff03_8a12).status == -1 && decode_word(0x0000_0000_ff03_8a12).len == 0
);

/// What may go to endpoint 0x12 (proto::allowed): a request word of step 6's three commands, and at stage 7 the
/// identity's eight, nothing else.
pub(crate) fn request_allowed(msg: &Message) -> bool {
    let w = decode_word(msg.msg0);
    let identity = IDENTITY_ARMED.load(core::sync::atomic::Ordering::Relaxed)
        && matches!(
            w.cmd,
            CMD_CREATE_KEYBAG
                | CMD_COPY_KEYBAG
                | CMD_LOAD_KEYBAG
                | CMD_UNLOAD_KEYBAG
                | CMD_COPY_KEYBAG_UUID
                | CMD_MAKE_SYSTEM_KEYBAG
                | CMD_DEVICE_STATE_TRANSITION
                | CMD_GET_DEVICE_STATE
        );
    let cred = crate::proto::CRED_ARMED.load(core::sync::atomic::Ordering::Relaxed) && w.cmd == CMD_VERIFY_SECRET;
    msg.msg1 == 0
        && msg.msg0 as u8 == EP_SKS
        && (matches!(w.cmd, CMD_GET_CAPABILITIES | CMD_SET_ENV | CMD_NULL_D_KEY) || identity || cred)
        && w.status == 0
        && w.flags == 0
        && usize::from(w.len) > BODY_OFF
        && usize::from(w.len) <= BUF_LEN
}

// The kernel's lib/crypto, built in (CONFIG_CRYPTO_LIB_SHA1=y, CONFIG_CRYPTO_LIB_SHA256=y). bindgen has sha256()
// from a header the bindings include; sha1() it lacks, so it is declared here as include/crypto/sha1.h has it.
mod ffi {
    extern "C" {
        pub(super) fn sha1(data: *const u8, len: usize, out: *mut u8);
    }
}

pub(crate) fn sha256(d: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    // SAFETY: `d` is valid for `d.len()` bytes and `o` for the 32 that sha256() writes.
    unsafe { bindings::sha256(d.as_ptr(), d.len(), o.as_mut_ptr()) };
    o
}

pub(crate) fn sha1(d: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    // SAFETY: `d` is valid for `d.len()` bytes and `o` for the 20 that sha1() writes.
    unsafe { ffi::sha1(d.as_ptr(), d.len(), o.as_mut_ptr()) };
    o
}

/// FIPS 180's "abc" vectors through both bindings: the probe refuses stage 6 if either fails.
pub(crate) fn self_test() -> bool {
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    const SHA1_ABC: [u8; 20] = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    sha256(b"abc") == SHA256_ABC && sha1(b"abc") == SHA1_ABC
}

/// The digest's span of the header: 0x10..0x48 (v1) or 0x10..0x50 (v2); None for another version, which
/// __payload_hash refuses ("unexpected version").
fn hashed_header(version: u32) -> Option<core::ops::Range<usize>> {
    match version {
        1 => Some(0x10..0x48),
        2 => Some(0x10..0x50),
        _ => None,
    }
}

/// __payload_hash: SHA-256 of the header's span and the body, its first 16 bytes.
fn digest(hdr: &[u8; HEADER_LEN], body: &[u8]) -> Result<Option<[u8; DIGEST_LEN]>> {
    let Some(span) = hashed_header(u32::from_le_bytes([
        hdr[0x10], hdr[0x11], hdr[0x12], hdr[0x13],
    ])) else {
        return Ok(None);
    };
    let mut m = KVec::with_capacity(span.len() + body.len(), GFP_KERNEL)?;
    m.extend_from_slice(&hdr[span], GFP_KERNEL)?;
    m.extend_from_slice(body, GFP_KERNEL)?;
    let h = sha256(&m);
    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(&h[..DIGEST_LEN]);
    Ok(Some(d))
}

/// A body, as the coders write it.
pub(crate) struct Body(KVec<u8>);

impl Body {
    pub(crate) fn new() -> Self {
        Body(KVec::new())
    }

    pub(crate) fn word(mut self, v: u32) -> Result<Self> {
        self.0.extend_from_slice(&v.to_le_bytes(), GFP_KERNEL)?;
        Ok(self)
    }

    pub(crate) fn lword(mut self, v: u64) -> Result<Self> {
        self.0.extend_from_slice(&v.to_le_bytes(), GFP_KERNEL)?;
        Ok(self)
    }

    pub(crate) fn blob(mut self, b: &[u8]) -> Result<Self> {
        let n = u32::try_from(b.len()).map_err(|_| EINVAL)?;
        self.0.extend_from_slice(&n.to_le_bytes(), GFP_KERNEL)?;
        self.0.extend_from_slice(b, GFP_KERNEL)?;
        while self.0.len() % 4 != 0 {
            self.0.push(0, GFP_KERNEL)?;
        }
        Ok(self)
    }
}

/// The kernel's requests' body start: struct version 0, then the u64 1 (init_sep_endpoint, set_env(false),
/// effaceable_init all pass 1).
pub(crate) fn body_start() -> Result<Body> {
    Body::new().word(0)?.lword(1)
}

/// The environment set_env sends; `mode` is /defaults/cpx-encryption-mode.
pub(crate) fn set_env_blob(mode: u32) -> [u8; SET_ENV_LEN] {
    let mut e = [0u8; SET_ENV_LEN];
    e[0..4].copy_from_slice(&1u32.to_le_bytes());
    e[4..8].copy_from_slice(&mode.to_le_bytes());
    e[8..12].copy_from_slice(&4u32.to_le_bytes());
    e
}

/// A request image: the header gen_ipc_header makes with no process, its digest, the body.
pub(crate) fn build_request(
    version: u32,
    usec: u64,
    calendar_s: u64,
    body: &Body,
) -> Result<KVec<u8>> {
    if hashed_header(version).is_none() {
        return Err(EINVAL);
    }
    let mut hdr = [0u8; HEADER_LEN];
    hdr[0x10..0x14].copy_from_slice(&version.to_le_bytes());
    hdr[0x14..0x1c].copy_from_slice(&usec.to_le_bytes());
    // 0x1c flags 0 (__ipc_msg_process_extended_header clears bit 1 on a request), 0x20 0, 0x28 the uniqueid 0,
    // 0x30 the credential word 0; 0x34 the SHA-1 of the uniqueid's 8 bytes.
    let cd = sha1(&hdr[0x28..0x30]);
    hdr[0x34..0x48].copy_from_slice(&cd);
    if version == 2 {
        hdr[0x48..0x50].copy_from_slice(&calendar_s.to_le_bytes());
    }
    let d = digest(&hdr, &body.0)?.ok_or(EINVAL)?;
    hdr[..DIGEST_LEN].copy_from_slice(&d);

    let mut img = KVec::with_capacity(BODY_OFF + body.0.len(), GFP_KERNEL)?;
    img.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes(), GFP_KERNEL)?;
    img.extend_from_slice(&hdr, GFP_KERNEL)?;
    img.extend_from_slice(&body.0, GFP_KERNEL)?;
    if img.len() > BUF_LEN {
        return Err(EINVAL);
    }
    Ok(img)
}

// macOS 14.8.3's image lengths (the words' bytes 6-7 at sep-1.log 2184, 2193, 2221)
static_assert!(BODY_OFF + 4 + 8 + 4 == 0x64);
static_assert!(BODY_OFF + 4 + 8 + 4 + SET_ENV_LEN == 0x470);
static_assert!(BODY_OFF + 4 + 8 == 0x60);

/// A reply image, parsed as the coders parse it.
pub(crate) struct ReplyImage<'a> {
    pub(crate) header_len: u32,
    pub(crate) version: u32,
    pub(crate) usec: u64,
    pub(crate) flags: u32,
    /// The extended header's length, when a v2 header has flags bit 1.
    pub(crate) ext_len: Option<usize>,
    /// The digest checked as __payload_hash checks it; None for a version it refuses.
    pub(crate) digest_ok: Option<bool>,
    pub(crate) body: &'a [u8],
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(off..off.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// A u32 length, then that many bytes padded to 4: the end offset, or None past `b`.
fn blob_end(b: &[u8], off: usize) -> Option<usize> {
    let n = usize::try_from(u32_at(b, off)?).ok()?;
    let end = off.checked_add(4)?.checked_add(n.checked_add(3)? & !3)?;
    (end <= b.len()).then_some(end)
}

pub(crate) fn parse_reply(img: &[u8]) -> core::result::Result<ReplyImage<'_>, &'static str> {
    let header_len = u32_at(img, 0).ok_or("shorter than its header length")?;
    if header_len == 0 {
        return Err("no header");
    }
    let hdr_end = blob_end(img, 0).ok_or("a header longer than the image")?;
    let mut hdr = [0u8; HEADER_LEN];
    let n = (header_len as usize).min(HEADER_LEN);
    hdr[..n].copy_from_slice(&img[4..4 + n]);
    let version = u32_at(&hdr, 0x10).unwrap_or(0);
    let flags = u32_at(&hdr, 0x1c).unwrap_or(0);
    let digest_ok = digest(&hdr, &img[hdr_end..])
        .map_err(|_| "no memory for the digest")?
        .map(|d| d == hdr[..DIGEST_LEN]);
    let (ext_len, body_off) = if version >= 2 && flags & 2 != 0 {
        let end = blob_end(img, hdr_end).ok_or("an extended header longer than the image")?;
        (Some(end - hdr_end - 4), end)
    } else {
        (None, hdr_end)
    };
    Ok(ReplyImage {
        header_len,
        version,
        usec: u64_at(&hdr, 0x14).unwrap_or(0),
        flags,
        ext_len,
        digest_ok,
        body: &img[body_off..],
    })
}

/// get_capabilities' reply body (_code_ipc_get_capabilities 0xfffffe0009d0b570, the decode): struct version 0,
/// the u64 that is the SEP's header version (init_sep_endpoint takes min(2, it)), a blob, and nothing after
/// (14.8.3's: an empty blob, 0x5c = 4 + 0x48 + 4 + 8 + 4). Returns the u64 and the blob's length.
pub(crate) fn parse_capabilities(body: &[u8]) -> Option<(u64, usize)> {
    if u32_at(body, 0)? != 0 {
        return None;
    }
    let theirs = u64_at(body, 4)?;
    let blob = usize::try_from(u32_at(body, 12)?).ok()?;
    (blob_end(body, 12)? == body.len()).then_some((theirs, blob))
}

/// set_env's reply body (_code_ipc_set_env 0xfffffe0009d06bc4, the decode): struct version 0 and nothing after.
pub(crate) fn parse_version_only(body: &[u8]) -> bool {
    body.len() == 4 && u32_at(body, 0) == Some(0)
}

// --- stage 7: the identity key bag (macOS 27.2) ---

/// The kernel's client word, as step 6's start-up (identity_create passes the user client's; the kernel's own
/// requests 1).
const CLIENT: u64 = 1;

/// create_keybag version 5, as identity_create (rda AppleSEPKeyStore_272, 27.0.1's 0xfffffe0009d6f6e0) calls
/// __ipc_create_keybag_v5 (0xfffffe0009d7209c) and _code_ipc_create_keybag (0xfffffe0009d5664c) codes it: word 5,
/// lword client, word the flags (identity_create's options 0: 0), word the parent (-1), blob the secret, blob the
/// second OSData (none), blob the 16-byte UUID, fv_data (a blob; none), lword (options bit 1 << 8: 0), lword (the
/// hash's u32: 0), blob (the hash's salt: none).
pub(crate) fn create_identity(secret: &[u8], uuid: &[u8; 16]) -> Result<Body> {
    Body::new()
        .word(5)?
        .lword(CLIENT)?
        .word(0)?
        .word(u32::MAX)?
        .blob(secret)?
        .blob(&[])?
        .blob(uuid)?
        .blob(&[])?
        .lword(0)?
        .lword(0)?
        .blob(&[])
}

/// copy_keybag version 0 (_code_ipc_copy_keybag, 27.2's 0xfffffe0009d81998): lword client, word handle. The reply:
/// word 0, blob the wrapped bag, which load_keybag takes back. 27.2's AppleKeyStore::copy_keybag sends version 1,
/// which adds a blob the user client may pass; version 0 is the form without it.
pub(crate) fn copy_keybag(handle: i32) -> Result<Body> {
    Body::new().word(0)?.lword(CLIENT)?.word(handle as u32)
}

/// copy_keybag_uuid version 0 (_code_ipc_copy_keybag_uuid, 27.2's 0xfffffe0009d82208): lword client, word handle.
/// The reply: word 0, blob the bag's UUID.
pub(crate) fn copy_keybag_uuid(handle: i32) -> Result<Body> {
    Body::new().word(0)?.lword(CLIENT)?.word(handle as u32)
}

/// load_keybag version 0 (_code_ipc_load_keybag 0xfffffe0009d56e94): lword client, blob: a wrapped bag, or for
/// identity_open the identity's 16-byte UUID.
pub(crate) fn load_keybag(bag: &[u8]) -> Result<Body> {
    Body::new().word(0)?.lword(CLIENT)?.blob(bag)
}

/// unload_keybag version 0 (_code_ipc_unload_keybag 0xfffffe0009d57330): lword client, word handle.
pub(crate) fn unload_keybag(handle: i32) -> Result<Body> {
    Body::new().word(0)?.lword(CLIENT)?.word(handle as u32)
}

/// make_system_keybag version 1, as identity_load calls __ipc_make_system_keybag_v1 (27.0.1's 0xfffffe0009d5424c,
/// coded by 0xfffffe0009d5869c): lword client, word the opened handle, word the session handle, blob (none), lword
/// (0).
pub(crate) fn make_system_keybag(handle: i32, session: i32) -> Result<Body> {
    Body::new()
        .word(1)?
        .lword(CLIENT)?
        .word(handle as u32)?
        .word(session as u32)?
        .blob(&[])?
        .lword(0)
}

/// device_state_transition version 0 (_code_ipc_device_state_transition, 27.2's 0xfffffe0009d85030), macOS's identity
/// unlock: AppleKeyStore.framework's AKSIdentityUnlockSession calls the user client's selector 0x7b
/// (AKSIdentityUnlockInternal, 27.2's dyld cache 0x187d77d6c), which reaches unlock_the_device (0xfffffe0009d66e58):
/// lword client, word the session handle, word the state (0), lword the flags (0; 0x100 for selector 0x9a), blob the
/// secret. The reply: word 0, lword the action mask handle_device_state_return reads, lword the lock timer's time.
pub(crate) fn device_state_unlock(session: i32, secret: &[u8]) -> Result<Body> {
    Body::new()
        .word(0)?
        .lword(CLIENT)?
        .word(session as u32)?
        .word(0)?
        .lword(0)?
        .blob(secret)
}

/// verify_secret version 1, as 27.2's AppleKeyStore::identity_verify (rda AppleSEPKeyStore_272 0xfffffe0009d71624)
/// sends it: it loads the wrapped bag, calls verify_password (0xfffffe0009d692f8) with the loaded handle, the secret,
/// the ACM context and the flags 0x100 (its arguments 0, 1, and the caller's flag, 0x200, unset), then unloads it.
/// __ipc_verify_secret_v1 (0xfffffe0009d7fc0c) and _code_ipc_verify_secret (0xfffffe0009d86504): word 1, lword client,
/// word the handle, blob the secret, blob the ACM context's 16-byte handle, lword the flags. The reply: word 1, lword the
/// action mask handle_device_state_return reads, as the unlock's.
/// Step 10b's first run (build 19, 2026-11-08) sent that form, the kept bag loaded again, and the SEP answered -1 at
/// once; the form that passed (build 22) names the session's designated bag (-uid, stage 7's make_system_keybag) with
/// flags 0. cred_verify tries the forms in turn.
pub(crate) const VERIFY_FLAGS: u64 = 0x100;

pub(crate) fn verify_secret(handle: i32, secret: &[u8], acm: &[u8; crate::proto::ACM_HANDLE_LEN], flags: u64) -> Result<Body> {
    Body::new()
        .word(1)?
        .lword(CLIENT)?
        .word(handle as u32)?
        .blob(secret)?
        .blob(acm)?
        .lword(flags)
}

/// verify_secret's reply: word 1, the action mask.
pub(crate) fn parse_verify(body: &[u8]) -> Option<u64> {
    (body.len() == 12 && u32_at(body, 0)? == 1).then(|| u64_at(body, 4))?
}

/// create_keybag v5's reply: word 5, word the handle, fv_data (a blob). The handle and the blob's length.
pub(crate) fn parse_create_v5(body: &[u8]) -> Option<(i32, usize)> {
    if u32_at(body, 0)? != 5 {
        return None;
    }
    let handle = u32_at(body, 4)? as i32;
    let fv = usize::try_from(u32_at(body, 8)?).ok()?;
    (blob_end(body, 8)? == body.len()).then_some((handle, fv))
}

/// A reply of word 0 and one blob filling the body (copy_keybag, copy_keybag_uuid): the blob.
pub(crate) fn parse_blob(body: &[u8]) -> Option<&[u8]> {
    if u32_at(body, 0)? != 0 || blob_end(body, 4)? != body.len() {
        return None;
    }
    let n = usize::try_from(u32_at(body, 4)?).ok()?;
    body.get(8..8 + n)
}

/// load_keybag's reply: word 0, word the handle, nothing after.
pub(crate) fn parse_handle(body: &[u8]) -> Option<i32> {
    (body.len() == 8 && u32_at(body, 0)? == 0).then(|| u32_at(body, 4).map(|h| h as i32))?
}

/// A reply of its struct version alone (unload_keybag 0, make_system_keybag 1).
pub(crate) fn parse_version(body: &[u8], version: u32) -> bool {
    body.len() == 4 && u32_at(body, 0) == Some(version)
}

/// get_device_state version 0 (_code_ipc_get_device_state, 27.2's 0xfffffe0009d85270, command 0x19 in the table at
/// 0xfffffe00082fb4b8), as AppleKeyStore::get_device_state (0xfffffe0009d66828) sends it: lword client, word the
/// handle, word 0. The reply: word 0, blob a DER dictionary (the lock state, the generation: AppleKeyStore::generation
/// reads der_key_state_generation_state from it). A read.
pub(crate) fn get_device_state(handle: i32) -> Result<Body> {
    Body::new().word(0)?.lword(CLIENT)?.word(handle as u32)?.word(0)
}

/// The lock state (`sls`, der_key_state_lock_state: 1 locked, 0 unlocked) in get_device_state's DER dictionary: the
/// pair SEQUENCE {UTF8String "sls", INTEGER n} with a one-byte n, as the SEP writes it.
pub(crate) fn lock_state(dict: &[u8]) -> Option<u8> {
    const KEY: [u8; 9] = [0x30, 0x08, 0x0c, 0x03, b's', b'l', b's', 0x02, 0x01];
    dict.windows(KEY.len() + 1).find(|w| w[..KEY.len()] == KEY).map(|w| w[KEY.len()])
}

/// device_state_transition's reply: word 0, the action mask, the lock timer's time.
pub(crate) fn parse_device_state(body: &[u8]) -> Option<(u64, u64)> {
    (body.len() == 20 && u32_at(body, 0)? == 0)
        .then(|| Some((u64_at(body, 4)?, u64_at(body, 12)?)))?
}

/// The error AppleKeyStore::handle_device_state_return (27.2's 0xfffffe0009d66a60) makes of an action mask: 0x20
/// before 0x10 before 0x8 (keystore errors, IOKit subsystem 0x1f, and kIOReturnNotReadable); None for none of them.
/// Bit 0 arms the lock timer, 4 and 0x40 notify a state change, 0x80 posts a client event. An identity unlock answers
/// 0x20, which AKSIdentityUnlockInternal takes as success, as it takes 0.
pub(crate) fn state_error(mask: u64) -> Option<u32> {
    if mask & 0x20 != 0 {
        Some(0xe007_c01e)
    } else if mask & 0x10 != 0 {
        Some(0xe000_02ce)
    } else if mask & 0x8 != 0 {
        Some(0xe007_c014)
    } else {
        None
    }
}
