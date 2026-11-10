// SPDX-License-Identifier: GPL-2.0-only

//! The FIDO2 authenticator's resident credentials (CTAP2's discoverable credentials, passkeys): what the
//! authenticator keeps so that a relying party's ID alone finds the user's credentials. A credential stays what
//! fido.rs makes without one, its ID holding the ref key that only this Mac's SEP opens; the store adds the list
//! that finds it: per entry the RP's ID and its hash, the user's handle and names, and the credential's ID.
//!
//! The list is kept in two files the driver reads and writes whole (store.c): "SEPR", u8 the version, u64 the
//! generation, u16 the wrapped key's length, the store's key wrapped by the SEP (Keys::seal), u32 the ciphertext's
//! length, the ciphertext, and a 32-byte HMAC over all before it. The ciphertext is AES-256-CBC (a zero IV) of 16
//! random bytes, the list and PKCS#7 padding; its key and the HMAC's are HMACs of the store's key. A save writes the
//! file that does not hold the newest generation and syncs it before the request answers, so a cut write leaves the
//! list before it; the load takes the valid file of the higher generation. A file that could not be judged (not
//! read, or the SEP did not unwrap its key) stops the load rather than letting the other stand in: a save over it
//! would lose what it holds. Nothing outside the two files anchors the generation: whoever can write the directory
//! puts an older pair back, and with it the credentials deleted since.

use kernel::prelude::*;

use crate::fido::{aes_cbc, hmac, same, Keys};

/// The most credentials kept.
pub(crate) const MAX_ENTRIES: usize = 64;
/// The largest file taken: MAX_ENTRIES entries of the longest fields fit.
pub(crate) const FILE_MAX: usize = 0x20000;
/// The longest RP ID kept (a DNS name), user handle (CTAP2's limit) and name (WebAuthn's recommended cut).
pub(crate) const RP_MAX: usize = 255;
pub(crate) const USER_ID_MAX: usize = 64;
pub(crate) const NAME_MAX: usize = 64;
/// The longest credential ID kept.
pub(crate) const CRED_MAX: usize = 1023;

const MAGIC: &[u8; 4] = b"SEPR";
const VERSION: u8 = 1;
const ENC_LABEL: &[u8] = b"apple-sep-fido store enc";
const MAC_LABEL: &[u8] = b"apple-sep-fido store mac";
/// "SEPR", the version, the generation, the wrapped key's length.
const HEAD: usize = 4 + 1 + 8 + 2;

/// One resident credential.
pub(crate) struct Resident {
    pub(crate) rp_hash: [u8; 32],
    pub(crate) rp_id: KVec<u8>,
    pub(crate) user_id: KVec<u8>,
    pub(crate) user_name: KVec<u8>,
    pub(crate) user_display: KVec<u8>,
    pub(crate) cred_id: KVec<u8>,
    /// The order of creation: the newest answers first.
    seq: u32,
}

/// `b` copied, at most `max` bytes of it; a text is cut before a character it would split (its UTF-8 continuation
/// bytes), so it stays a text.
fn kept(b: &[u8], max: usize) -> Result<KVec<u8>> {
    let mut n = b.len().min(max);
    if n < b.len() {
        while n > 0 && b[n] & 0xc0 == 0x80 {
            n -= 1;
        }
    }
    let mut v = KVec::new();
    v.extend_from_slice(&b[..n], GFP_KERNEL)?;
    Ok(v)
}

impl Resident {
    pub(crate) fn new(rp_hash: &[u8; 32], rp_id: &[u8], user_id: &[u8], user_name: &[u8], user_display: &[u8], cred_id: &[u8]) -> Result<Resident> {
        if rp_id.len() > RP_MAX || user_id.len() > USER_ID_MAX || cred_id.len() > CRED_MAX {
            return Err(EINVAL);
        }
        Ok(Resident {
            rp_hash: *rp_hash,
            rp_id: kept(rp_id, RP_MAX)?,
            user_id: kept(user_id, USER_ID_MAX)?,
            user_name: kept(user_name, NAME_MAX)?,
            user_display: kept(user_display, NAME_MAX)?,
            cred_id: kept(cred_id, CRED_MAX)?,
            seq: 0,
        })
    }
}

/// Why a file did not open: it is not a list of ours (damaged, cut, another format), or that could not be told (the
/// SEP did not unwrap its key, no memory).
enum Bad {
    Invalid,
    Unknown,
}

/// What a file held.
struct Opened {
    generation: u64,
    key: [u8; 32],
    wrapped: KVec<u8>,
    list: KVec<Resident>,
}

/// The list and where it stands against the disk.
pub(crate) struct Store {
    list: KVec<Resident>,
    /// The newest generation on the disk and the file (0 or 1) that holds it; 0 with no file yet.
    generation: u64,
    slot: u8,
    /// The store's key and its wrapped form, from the file read or made at the first save.
    key: Option<([u8; 32], KVec<u8>)>,
    /// The list is the disk's: a file was read or written. Until then each use reads again (no file yet is an
    /// empty list, and the root may not have been there).
    loaded: bool,
    next_seq: u32,
}

fn le16(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?)))
}

fn put_field(v: &mut KVec<u8>, f: &[u8]) -> Result {
    v.extend_from_slice(&(f.len() as u16).to_le_bytes(), GFP_KERNEL)?;
    v.extend_from_slice(f, GFP_KERNEL)?;
    Ok(())
}

fn take_field<'a>(b: &'a [u8], at: &mut usize, max: usize) -> Option<&'a [u8]> {
    let n = le16(b, *at)?;
    let f = b.get(*at + 2..*at + 2 + n)?;
    *at += 2 + n;
    (n <= max).then_some(f)
}

impl Store {
    pub(crate) const fn new() -> Self {
        Store { list: KVec::new(), generation: 0, slot: 1, key: None, loaded: false, next_seq: 1 }
    }

    /// The list as the disk has it, read once a file exists: true when it may be used and saved over. False when a
    /// file is there that does not open (another Mac's, another key bag's, damaged): nothing is written over it but
    /// by clear().
    pub(crate) fn load(&mut self, k: &dyn Keys) -> bool {
        if self.loaded {
            return true;
        }
        let mut best: Option<(u8, Opened)> = None;
        let (mut present, mut unknown) = (false, false);
        for slot in 0..2u8 {
            match k.store_read(slot) {
                Ok(None) => {}
                Ok(Some(file)) => {
                    present = true;
                    match Self::open(k, &file) {
                        Ok(o) => {
                            if best.as_ref().is_none_or(|(_, b)| o.generation > b.generation) {
                                best = Some((slot, o));
                            }
                        }
                        Err(Bad::Invalid) => {}
                        Err(Bad::Unknown) => unknown = true,
                    }
                }
                Err(()) => {
                    present = true;
                    unknown = true;
                }
            }
        }
        // a file that could not be judged may be the newer one: the other does not stand in for it
        if unknown {
            self.list = KVec::new();
            return false;
        }
        match best {
            Some((slot, o)) => {
                self.next_seq = o.list.iter().map(|r| r.seq).max().unwrap_or(0).wrapping_add(1);
                self.list = o.list;
                self.generation = o.generation;
                self.slot = slot;
                self.key = Some((o.key, o.wrapped));
                self.loaded = true;
                true
            }
            None => {
                self.list = KVec::new();
                self.generation = 0;
                self.slot = 1;
                !present
            }
        }
    }

    /// One file opened: its HMAC under the key the SEP unwraps, then the list.
    fn open(k: &dyn Keys, file: &[u8]) -> core::result::Result<Opened, Bad> {
        use Bad::{Invalid, Unknown};
        if file.len() < HEAD + 4 + 32 || &file[..4] != MAGIC || file[4] != VERSION {
            return Err(Invalid);
        }
        let generation = u64::from_le_bytes(file[5..13].try_into().map_err(|_| Invalid)?);
        let wlen = le16(file, 13).ok_or(Invalid)?;
        let wrapped = file.get(HEAD..HEAD + wlen).ok_or(Invalid)?;
        let at = HEAD + wlen;
        let clen = u32::from_le_bytes(file.get(at..at + 4).ok_or(Invalid)?.try_into().map_err(|_| Invalid)?) as usize;
        let ct = file.get(at + 4..at.checked_add(4 + clen).ok_or(Invalid)?).ok_or(Invalid)?;
        let mac = file.get(at + 4 + clen..).ok_or(Invalid)?;
        if mac.len() != 32 || clen < 32 || clen % 16 != 0 {
            return Err(Invalid);
        }
        // the SEP's no: another Mac's or bag's key, or a request that failed
        let mut plain = k.unseal(wrapped).ok_or(Unknown)?;
        let mut key = [0u8; 32];
        let whole = plain.len() == 32;
        if whole {
            key.copy_from_slice(&plain);
        }
        plain.iter_mut().for_each(|b| *b = 0);
        if !whole || !same(&hmac(&hmac(&key, MAC_LABEL), &file[..at + 4 + clen]), mac) {
            key.fill(0);
            return Err(Invalid);
        }
        let mut body = KVec::new();
        if body.extend_from_slice(ct, GFP_KERNEL).is_err() {
            key.fill(0);
            return Err(Unknown);
        }
        if !aes_cbc(&hmac(&key, ENC_LABEL), false, &mut body) {
            key.fill(0);
            return Err(Invalid);
        }
        let list = Self::parse(&body);
        body.iter_mut().for_each(|b| *b = 0);
        let list = match list {
            Ok(list) => list,
            Err(why) => {
                key.fill(0);
                return Err(why);
            }
        };
        let mut w = KVec::new();
        if w.extend_from_slice(wrapped, GFP_KERNEL).is_err() {
            key.fill(0);
            return Err(Unknown);
        }
        Ok(Opened { generation, key, wrapped: w, list })
    }

    /// The plaintext: 16 random bytes, u16 the count, the entries, PKCS#7 padding.
    fn parse(body: &[u8]) -> core::result::Result<KVec<Resident>, Bad> {
        use Bad::{Invalid, Unknown};
        let pad = usize::from(*body.last().ok_or(Invalid)?);
        if pad == 0 || pad > 16 || body.len() < 16 + 2 + pad || body[body.len() - pad..].iter().any(|&b| usize::from(b) != pad) {
            return Err(Invalid);
        }
        let b = &body[16..body.len() - pad];
        let n = le16(b, 0).ok_or(Invalid)?;
        if n > MAX_ENTRIES {
            return Err(Invalid);
        }
        let mut at = 2;
        let mut list = KVec::new();
        for _ in 0..n {
            let rp_hash: [u8; 32] = b.get(at..at + 32).ok_or(Invalid)?.try_into().map_err(|_| Invalid)?;
            let seq = u32::from_le_bytes(b.get(at + 32..at + 36).ok_or(Invalid)?.try_into().map_err(|_| Invalid)?);
            at += 36;
            let rp_id = take_field(b, &mut at, RP_MAX).ok_or(Invalid)?;
            let user_id = take_field(b, &mut at, USER_ID_MAX).ok_or(Invalid)?;
            let user_name = take_field(b, &mut at, NAME_MAX).ok_or(Invalid)?;
            let user_display = take_field(b, &mut at, NAME_MAX).ok_or(Invalid)?;
            let cred_id = take_field(b, &mut at, CRED_MAX).ok_or(Invalid)?;
            // the fields' lengths were checked: what is left to fail is memory
            let mut r = Resident::new(&rp_hash, rp_id, user_id, user_name, user_display, cred_id).map_err(|_| Unknown)?;
            r.seq = seq;
            list.push(r, GFP_KERNEL).map_err(|_| Unknown)?;
        }
        if at != b.len() {
            return Err(Invalid);
        }
        Ok(list)
    }

    /// The list written as the next generation and synced; false leaves the disk's files as they were (the one
    /// written over held the older generation) and forgets the list, so the next use reads the disk again.
    pub(crate) fn save(&mut self, k: &dyn Keys) -> bool {
        let done = self.write(k).is_some();
        if !done {
            self.loaded = false;
            self.list = KVec::new();
        }
        done
    }

    fn write(&mut self, k: &dyn Keys) -> Option<()> {
        if self.key.is_none() {
            let mut key = [0u8; 32];
            k.random(&mut key);
            let wrapped = k.seal(&key);
            match wrapped {
                Some(w) if w.len() <= 0xffff => self.key = Some((key, w)),
                _ => {
                    key.fill(0);
                    return None;
                }
            }
        }
        let (key, wrapped) = self.key.as_ref()?;
        let mut body = KVec::new();
        let mut iv = [0u8; 16];
        k.random(&mut iv);
        body.extend_from_slice(&iv, GFP_KERNEL).ok()?;
        body.extend_from_slice(&(self.list.len() as u16).to_le_bytes(), GFP_KERNEL).ok()?;
        for r in self.list.iter() {
            body.extend_from_slice(&r.rp_hash, GFP_KERNEL).ok()?;
            body.extend_from_slice(&r.seq.to_le_bytes(), GFP_KERNEL).ok()?;
            for f in [&r.rp_id, &r.user_id, &r.user_name, &r.user_display, &r.cred_id] {
                put_field(&mut body, f).ok()?;
            }
        }
        let pad = 16 - body.len() % 16;
        for _ in 0..pad {
            body.push(pad as u8, GFP_KERNEL).ok()?;
        }
        let enc = aes_cbc(&hmac(key, ENC_LABEL), true, &mut body);
        if !enc {
            body.iter_mut().for_each(|b| *b = 0);
            return None;
        }
        let generation = self.generation + 1;
        let mut file = KVec::new();
        file.extend_from_slice(MAGIC, GFP_KERNEL).ok()?;
        file.push(VERSION, GFP_KERNEL).ok()?;
        file.extend_from_slice(&generation.to_le_bytes(), GFP_KERNEL).ok()?;
        file.extend_from_slice(&(wrapped.len() as u16).to_le_bytes(), GFP_KERNEL).ok()?;
        file.extend_from_slice(wrapped, GFP_KERNEL).ok()?;
        file.extend_from_slice(&(body.len() as u32).to_le_bytes(), GFP_KERNEL).ok()?;
        file.extend_from_slice(&body, GFP_KERNEL).ok()?;
        let mac = hmac(&hmac(key, MAC_LABEL), &file);
        file.extend_from_slice(&mac, GFP_KERNEL).ok()?;
        if file.len() > FILE_MAX {
            return None;
        }
        let slot = 1 - self.slot;
        if !k.store_write(slot, &file) {
            return None;
        }
        self.generation = generation;
        self.slot = slot;
        self.loaded = true;
        Some(())
    }

    /// A credential added, in place of the user's older one for the RP (the same hash and handle); false when the
    /// store is full or out of memory.
    pub(crate) fn put(&mut self, mut r: Resident) -> bool {
        r.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if let Some(old) = self.list.iter_mut().find(|o| o.rp_hash == r.rp_hash && o.user_id[..] == r.user_id[..]) {
            *old = r;
            return true;
        }
        self.list.len() < MAX_ENTRIES && self.list.push(r, GFP_KERNEL).is_ok()
    }

    /// The RP's credentials, the newest first.
    pub(crate) fn find(&self, rp_hash: &[u8; 32]) -> Result<KVec<&Resident>> {
        let mut v = KVec::new();
        for r in self.list.iter().filter(|r| &r.rp_hash == rp_hash) {
            v.push(r, GFP_KERNEL)?;
        }
        v.sort_unstable_by(|a, b| b.seq.cmp(&a.seq));
        Ok(v)
    }

    /// Whether a credential of this ID is kept.
    pub(crate) fn has(&self, cred_id: &[u8]) -> bool {
        self.list.iter().any(|r| r.cred_id[..] == *cred_id)
    }

    /// The credential of this ID, if kept.
    pub(crate) fn get(&self, cred_id: &[u8]) -> Option<&Resident> {
        self.list.iter().find(|r| r.cred_id[..] == *cred_id)
    }

    /// Every credential, in the order kept.
    pub(crate) fn all(&self) -> &[Resident] {
        &self.list
    }

    /// The credential of this ID dropped; whether there was one.
    pub(crate) fn remove(&mut self, cred_id: &[u8]) -> bool {
        let n = self.list.len();
        self.list.retain(|r| r.cred_id[..] != *cred_id);
        self.list.len() != n
    }

    /// The names of the credential of this ID replaced, for the same user handle; whether there was one.
    pub(crate) fn rename(&mut self, cred_id: &[u8], user_id: &[u8], name: &[u8], display: &[u8]) -> Result<bool> {
        let Some(r) = self.list.iter_mut().find(|r| r.cred_id[..] == *cred_id && r.user_id[..] == *user_id) else {
            return Ok(false);
        };
        let (name, display) = (kept(name, NAME_MAX)?, kept(display, NAME_MAX)?);
        r.user_name = name;
        r.user_display = display;
        Ok(true)
    }

    /// Every credential dropped and the empty list saved over both files, the unreadable too (Reset).
    pub(crate) fn clear(&mut self, k: &dyn Keys) -> bool {
        let _ = self.load(k);
        self.list = KVec::new();
        self.loaded = true;
        self.save(k) && self.save(k)
    }

    /// The store's key forgotten (the driver going).
    pub(crate) fn forget(&mut self) {
        if let Some((key, _)) = self.key.as_mut() {
            key.fill(0);
        }
        self.key = None;
    }
}
