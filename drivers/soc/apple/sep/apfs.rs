// SPDX-License-Identifier: GPL-2.0-only
//
// The two files the SEP takes from the iBoot System Container, found by the driver on the partition itself instead of
// by the lab's script: the xART volume's `.gl` (its extents, through which disk.rs reads and writes it in place) and
// the Hardware volume's factory calibration `/FactoryData/System/Library/Caches/com.apple.factorydata/FSCl-<serial>`
// (its bytes, stage 12's input). A read-only APFS reader that reads the container as tools/re/apfs.py does (Apple's
// File System Reference): the newest checkpoint's container superblock, the object maps, the volume by its role, the
// file-system tree's directory entries, inodes, extended attributes and extents, and decmpfs's LZVN. Only what the two
// lookups take: no sealed or encrypted volume, no snapshot, no hole in a file, no zlib, LZFSE or LZBITMAP.
//
// The disk is not trusted: each object's Fletcher-64, type, subtype and oid are checked when it is read, every offset
// taken from it is checked against its block or record, and every walk is bounded (the checkpoint area, the B-trees'
// depth, the nodes one walk reads), so a damaged or hostile container gives an error, never a panic or an endless
// loop. core only: the caller reads the partition (Disk) and gives the buffers (SCRATCH bytes from the heap: the
// kernel's stack is 16 KiB).

/// The partition, read by the caller.
pub(crate) trait Disk {
    /// `buf.len()` bytes at the partition's byte offset `off`; an error past its end.
    fn read(&mut self, off: u64, buf: &mut [u8]) -> core::result::Result<(), &'static str>;
}

/// The container's block size (nx_block_size): the only one read.
pub(crate) const BLOCK: usize = 4096;
/// The scratch the caller gives: three blocks (a container superblock, a B-tree node, a window on a resource fork).
pub(crate) const SCRATCH: usize = 3 * BLOCK;

type Result<T = ()> = core::result::Result<T, &'static str>;

/// A walk's visitor of file-system records: the disk (to read what a record points at), the key and the value; false
/// ends the walk.
type Records<'v, D> = dyn FnMut(&mut D, &[u8], &[u8]) -> Result<bool> + 'v;
/// A visitor of directory entries: the name, the inode and its type; false ends the walk.
type Entries<'v> = dyn FnMut(&[u8], u64, u16) -> Result<bool> + 'v;

const NX_MAGIC: &[u8; 4] = b"NXSB";
const APSB_MAGIC: &[u8; 4] = b"APSB";
// o_type's low 16 bits, and o_subtype
const OBJ_NX: u32 = 0x1;
const OBJ_BTREE: u32 = 0x2;
const OBJ_BTREE_NODE: u32 = 0x3;
const OBJ_OMAP: u32 = 0xb;
const OBJ_FS: u32 = 0xd;
const OBJ_FSTREE: u32 = 0xe;
// btn_flags
const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED: u16 = 0x4;
const BTNODE_HASHED: u16 = 0x8;
/// ov_flags refused: OMAP_VAL_DELETED, OMAP_VAL_ENCRYPTED, OMAP_VAL_NOHEADER (no checksum to check).
const OMAP_VAL_REFUSED: u32 = 0x1 | 0x4 | 0x8;
// j_key_t's kinds
const J_INODE: u8 = 3;
const J_XATTR: u8 = 4;
const J_FILE_EXTENT: u8 = 8;
const J_DIR_REC: u8 = 9;
const ROOT_DIR: u64 = 2;
const INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const INCOMPAT_NORM_INSENSITIVE: u64 = 0x8;
const INCOMPAT_SEALED: u64 = 0x20;
const FS_UNENCRYPTED: u64 = 0x1;
const ROLE_XART: u16 = 0x100;
const ROLE_HARDWARE: u16 = 0x140;
const INO_EXT_DSTREAM: u8 = 8;
const XATTR_DATA_EMBEDDED: u16 = 0x2;
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;
/// bsd_flags: the file's data is in its decmpfs attributes.
const UF_COMPRESSED: u32 = 0x20;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
/// decmpfs's chunks in a resource fork.
const CHUNK: usize = 0x10000;

/// The most blocks of the checkpoint descriptor area searched for the newest superblock (the ISC's has 16).
const DESC_MAX: u32 = 1024;
/// The most volumes in a container (NX_MAX_FILE_SYSTEMS).
const VOLUMES: u32 = 100;
/// The most levels of a B-tree: a root at level 7 (the ISC's are at level 0 or 1).
const DEPTH: usize = 8;
/// The most file-system tree nodes one walk reads.
const NODES: u32 = 1024;

/// The calibration's directory on the Hardware volume.
const CALIBRATION_DIR: [&[u8]; 5] = [b"FactoryData", b"System", b"Library", b"Caches", b"com.apple.factorydata"];

/// `N` bytes at `at`, or an error past the end of `d`.
fn bytes<const N: usize>(d: &[u8], at: usize) -> Result<[u8; N]> {
    d.get(at..).and_then(|d| d.first_chunk::<N>()).copied().ok_or("a field past the end of its APFS object or record")
}

fn le16(d: &[u8], at: usize) -> Result<u16> {
    bytes(d, at).map(u16::from_le_bytes)
}

fn le32(d: &[u8], at: usize) -> Result<u32> {
    bytes(d, at).map(u32::from_le_bytes)
}

fn le64(d: &[u8], at: usize) -> Result<u64> {
    bytes(d, at).map(u64::from_le_bytes)
}

/// A name without its NUL terminator.
fn trim(mut n: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = n {
        n = rest;
    }
    n
}

/// APFS's Fletcher-64 over a block from byte 8 (apfs.py's fletcher64).
fn fletcher64(b: &[u8; BLOCK]) -> u64 {
    const M: u64 = 0xffff_ffff;
    let (mut s1, mut s2) = (0u64, 0u64);
    for w in b.chunks_exact(4).skip(2) {
        let x = w.iter().rev().fold(0u64, |x, &b| (x << 8) | u64::from(b));
        s1 = (s1 + x) % M;
        s2 = (s2 + s1) % M;
    }
    let lo = M - (s1 + s2) % M;
    let hi = M - (s1 + lo) % M;
    (hi << 32) | lo
}

/// A block read as an object: its Fletcher-64, its type (o_type's low 16 bits) and subtype, and its oid.
fn check(b: &[u8; BLOCK], kind: u32, subtype: u32, oid: u64) -> Result {
    if le64(b, 0)? != fletcher64(b) {
        return Err("an APFS object fails its checksum");
    }
    if le32(b, 0x18)? & 0xffff != kind || le32(b, 0x1c)? != subtype {
        return Err("an APFS object is not of its reference's type");
    }
    if le64(b, 0x8)? != oid {
        return Err("an APFS object is not its reference's oid");
    }
    Ok(())
}

/// Whether `b` is a container superblock: its checksum good, "NXSB", 4096-byte blocks.
fn is_nx(b: &[u8; BLOCK]) -> bool {
    check(b, OBJ_NX, 0, 1).is_ok() && b.get(0x20..0x24) == Some(NX_MAGIC) && le32(b, 0x24) == Ok(BLOCK as u32)
}

/// The newest container superblock into `nx` (apfs.py's Container.latest): the checkpoint descriptor area's newest
/// valid one, else block 0's. `b` is scratch.
fn checkpoint<D: Disk>(disk: &mut D, nx: &mut [u8; BLOCK], b: &mut [u8; BLOCK]) -> Result {
    disk.read(0, nx)?;
    if !is_nx(nx) {
        return Err("the partition's block 0 is not an APFS container superblock with 4096-byte blocks");
    }
    let (count, base) = (le32(nx, 0x68)?, le64(nx, 0x70)?);
    // the top bit: the area is a B-tree of descriptors, not read (apfs.py keeps block 0's)
    if count & 0x8000_0000 != 0 {
        return Ok(());
    }
    if count > DESC_MAX {
        return Err("the container's checkpoint descriptor area is larger than the reader searches");
    }
    for i in 0..u64::from(count) {
        let at = base.checked_add(i).and_then(|n| n.checked_mul(BLOCK as u64)).ok_or("the checkpoint area overflows")?;
        disk.read(at, b)?;
        if is_nx(b) && le64(b, 0x10)? > le64(nx, 0x10)? {
            nx.copy_from_slice(b);
        }
    }
    Ok(())
}

/// A B-tree node's layout (btree_node_phys_t), checked against its block.
struct Node {
    leaf: bool,
    level: u16,
    count: usize,
    /// An object map's node: fixed 16-byte keys and values, an index node's values each a child's 8-byte oid.
    fixed: bool,
    /// The table of entries' start, the keys' start, the values' end (before a root's btree_info_t).
    toc: usize,
    keys: usize,
    vend: usize,
}

impl Node {
    /// The node in `b`: the root when `parent` is None, else one level below its parent; an object map's (`fixed`)
    /// or a file system's (variable-size entries).
    fn new(b: &[u8; BLOCK], parent: Option<u16>, fixed: bool) -> Result<Node> {
        let (flags, level, count) = (le16(b, 0x20)?, le16(b, 0x22)?, le32(b, 0x24)? as usize);
        let (toff, tlen) = (usize::from(le16(b, 0x28)?), usize::from(le16(b, 0x2a)?));
        let root = flags & BTNODE_ROOT != 0;
        let placed = match parent {
            None => root && usize::from(level) < DEPTH,
            Some(p) => !root && p > 0 && level == p - 1,
        };
        if !placed {
            return Err("a B-tree node out of place: a root under another node, or at the wrong level");
        }
        if (flags & BTNODE_LEAF != 0) != (level == 0) || flags & BTNODE_HASHED != 0 || (flags & BTNODE_FIXED != 0) != fixed
        {
            return Err("a B-tree node's flags do not fit its tree or its level");
        }
        let toc = 0x38 + toff;
        let keys = toc + tlen;
        let vend = if root { BLOCK - 0x28 } else { BLOCK };
        if keys > vend || count.checked_mul(if fixed { 4 } else { 8 }).is_none_or(|n| n > tlen) {
            return Err("a B-tree node's table overruns it");
        }
        // an object map's root says its keys and values are 16 bytes (btree_info_t's bt_key_size, bt_val_size)
        if fixed && root && (le32(b, BLOCK - 0x20)? != 16 || le32(b, BLOCK - 0x1c)? != 16) {
            return Err("an object map's B-tree without 16-byte keys and values");
        }
        Ok(Node { leaf: level == 0, level, count, fixed, toc, keys, vend })
    }

    /// Entry `i`'s key and value, None for an entry without a value.
    fn entry<'b>(&self, b: &'b [u8; BLOCK], i: usize) -> Result<Option<(&'b [u8], &'b [u8])>> {
        if i >= self.count {
            return Err("a B-tree node's entry past its count");
        }
        let (ko, kl, vo, vl) = if self.fixed {
            let e = self.toc + 4 * i;
            (le16(b, e)?, 16, le16(b, e + 2)?, if self.leaf { 16 } else { 8 })
        } else {
            let e = self.toc + 8 * i;
            (le16(b, e)?, le16(b, e + 2)?, le16(b, e + 4)?, le16(b, e + 6)?)
        };
        if vo == 0xffff {
            return Ok(None);
        }
        // keys from the keys' start, values back from the values' end, both between the two
        let area = b.get(self.keys..self.vend).ok_or("a B-tree node's table overruns it")?;
        let k = area.get(usize::from(ko)..).and_then(|a| a.get(..usize::from(kl)));
        let v = area.len().checked_sub(usize::from(vo)).and_then(|at| area.get(at..)).and_then(|a| a.get(..usize::from(vl)));
        match (k, v) {
            (Some(k), Some(v)) => Ok(Some((k, v))),
            _ => Err("a B-tree entry's key or value outside its node"),
        }
    }

    /// Index entry `i`'s child: its oid.
    fn child(&self, b: &[u8; BLOCK], i: usize) -> Result<u64> {
        let (_, v) = self.entry(b, i)?.ok_or("an index node's entry without a child")?;
        le64(v, 0)
    }
}

/// A file-system record's key header (j_key_t): its object's id and its kind.
fn key(k: &[u8]) -> Result<(u64, u8)> {
    let h = le64(k, 0)?;
    Ok((h & 0x0fff_ffff_ffff_ffff, (h >> 60) as u8))
}

/// A volume's file-system tree: its object map's B-tree and its root's virtual oid; whether its directory entries'
/// keys are hashed (a case- or normalisation-insensitive volume) and its names compared without case.
#[derive(Clone, Copy)]
struct Volume {
    omap: u64,
    root: u64,
    hashed: bool,
    fold: bool,
}

/// An extended attribute's value: embedded in its record (copied out, its length) or a data stream (its id and size).
enum Xattr {
    Embedded(usize),
    Stream(u64, u64),
}

/// The container at its newest checkpoint: the disk, the buffer its nodes are read into, the checkpoint's xid (the
/// object maps' newest entries at or before it are taken) and the container's size in blocks.
struct Fs<'a, D: Disk> {
    disk: &'a mut D,
    node: &'a mut [u8; BLOCK],
    xid: u64,
    blocks: u64,
}

impl<'a, D: Disk> Fs<'a, D> {
    /// The container at its newest checkpoint and its one volume of `role`, which must be neither sealed nor
    /// encrypted; `missing` is the error without one.
    fn open(
        disk: &'a mut D,
        nx: &mut [u8; BLOCK],
        node: &'a mut [u8; BLOCK],
        role: u16,
        missing: &'static str,
    ) -> Result<(Self, Volume)> {
        checkpoint(disk, nx, node)?;
        let blocks = le64(nx, 0x28)?;
        if blocks.checked_mul(BLOCK as u64).is_none() {
            return Err("the container's size overflows");
        }
        let mut fs = Fs { disk, node, xid: le64(nx, 0x10)?, blocks };
        let omap = fs.omap_tree(le64(nx, 0xa0)?)?;
        let count = le32(nx, 0xb4)?;
        if count > VOLUMES {
            return Err("the container has more volumes than APFS allows");
        }
        let mut found = None;
        for i in 0..count as usize {
            let oid = le64(nx, 0xb8 + 8 * i)?;
            if oid == 0 {
                continue;
            }
            let paddr = fs.lookup(omap, oid)?;
            fs.object(paddr, OBJ_FS, 0, oid)?;
            let b = &*fs.node;
            if b.get(0x20..0x24) != Some(APSB_MAGIC) {
                return Err("a volume superblock without its magic");
            }
            if le16(b, 0x3c4)? != role {
                continue;
            }
            if found.is_some() {
                return Err("two volumes of the role the reader looks for");
            }
            let (incompat, flags) = (le64(b, 0x38)?, le64(b, 0x108)?);
            if incompat & INCOMPAT_SEALED != 0 || flags & FS_UNENCRYPTED == 0 {
                return Err("the volume is sealed or encrypted: not read");
            }
            found = Some((le64(b, 0x80)?, le64(b, 0x88)?, incompat));
        }
        let (omap, root, incompat) = found.ok_or(missing)?;
        let vol = Volume {
            omap: fs.omap_tree(omap)?,
            root,
            hashed: incompat & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORM_INSENSITIVE) != 0,
            fold: incompat & INCOMPAT_CASE_INSENSITIVE != 0,
        };
        Ok((fs, vol))
    }

    /// The object at block `paddr` into the node buffer, checked (`check`).
    fn object(&mut self, paddr: u64, kind: u32, subtype: u32, oid: u64) -> Result {
        if paddr == 0 || paddr >= self.blocks {
            return Err("an APFS object's address is outside the container");
        }
        // below `blocks`, whose bytes fit a u64 (open)
        self.disk.read(paddr * BLOCK as u64, self.node.as_mut_slice())?;
        check(self.node, kind, subtype, oid)
    }

    /// The object map at block `paddr`: its B-tree's root (omap_phys_t's om_tree_oid).
    fn omap_tree(&mut self, paddr: u64) -> Result<u64> {
        self.object(paddr, OBJ_OMAP, 0, paddr)?;
        le64(self.node, 0x30)
    }

    /// The block of virtual object `oid` in the object map whose B-tree's root is at `tree` (apfs.py's lookup): its
    /// newest entry at or before the checkpoint's xid.
    fn lookup(&mut self, tree: u64, oid: u64) -> Result<u64> {
        let (mut paddr, mut parent) = (tree, None);
        // at most DEPTH nodes: each child is a level below its parent (Node::new)
        loop {
            self.object(paddr, if parent.is_none() { OBJ_BTREE } else { OBJ_BTREE_NODE }, OBJ_OMAP, paddr)?;
            let n = Node::new(self.node, parent, true)?;
            // the last entry at or below (oid, xid)
            let mut best = None;
            for i in 0..n.count {
                let Some((k, v)) = n.entry(self.node, i)? else { continue };
                let at = (le64(k, 0)?, le64(k, 8)?);
                if at > (oid, self.xid) {
                    break;
                }
                best = Some((at.0, v));
            }
            let (at, v) = best.ok_or("an object not in its object map")?;
            if n.leaf {
                if at != oid {
                    return Err("an object not in its object map");
                }
                if le32(v, 0)? & OMAP_VAL_REFUSED != 0 {
                    return Err("an object map's entry deleted, encrypted or without a header");
                }
                return le64(v, 8);
            }
            paddr = le64(v, 0)?;
            parent = Some(n.level);
        }
    }

    /// A node of the volume's file-system tree: virtual `oid` through its object map, its root when `parent` is None.
    fn fs_node(&mut self, vol: Volume, oid: u64, parent: Option<u16>, nodes: &mut u32) -> Result<Node> {
        if *nodes == NODES {
            return Err("a file-system tree walk read more nodes than the reader allows");
        }
        *nodes += 1;
        let paddr = self.lookup(vol.omap, oid)?;
        self.object(paddr, if parent.is_none() { OBJ_BTREE } else { OBJ_BTREE_NODE }, OBJ_FSTREE, oid)?;
        Node::new(self.node, parent, false)
    }

    /// The volume's file-system records in key order from the first leaf that may hold `start`'s, each (key, value)
    /// to `visit` until it returns false (apfs.py's scan). Down to that leaf, then on leaf by leaf, each next one
    /// found from its parent read again.
    fn scan(&mut self, vol: Volume, start: (u64, u8), visit: &mut Records<'_, D>) -> Result {
        const DEEP: &str = "a file-system tree deeper than the reader allows";
        // the index nodes from the root down: oid, level, the child taken
        let mut path = [(0u64, 0u16, 0usize); DEPTH];
        let mut depth = 0;
        let mut nodes = 0;
        let mut oid = vol.root;
        loop {
            // down from `oid` at `depth`, each index node's last child whose key is below `start` (else its first)
            let leaf = loop {
                let parent = match depth {
                    0 => None,
                    d => Some(path.get(d - 1).ok_or(DEEP)?.1),
                };
                let n = self.fs_node(vol, oid, parent, &mut nodes)?;
                if n.leaf {
                    break n;
                }
                let mut first = 0;
                for i in 0..n.count {
                    let (k, _) = n.entry(self.node, i)?.ok_or("an index node's entry without a child")?;
                    if key(k)? >= start {
                        break;
                    }
                    first = i;
                }
                *path.get_mut(depth).ok_or(DEEP)? = (oid, n.level, first);
                oid = n.child(self.node, first)?;
                depth += 1;
            };
            for i in 0..leaf.count {
                if let Some((k, v)) = leaf.entry(self.node, i)? {
                    if !visit(self.disk, k, v)? {
                        return Ok(());
                    }
                }
            }
            // up to the nearest index node with a child after the one taken, and down that child
            loop {
                let Some(d) = depth.checked_sub(1) else {
                    return Ok(());
                };
                depth = d;
                let (at, level, taken) = *path.get(d).ok_or(DEEP)?;
                let parent = match d {
                    0 => None,
                    d => Some(path.get(d - 1).ok_or(DEEP)?.1),
                };
                let n = self.fs_node(vol, at, parent, &mut nodes)?;
                if n.level != level {
                    return Err("a file-system tree node changed while it was read");
                }
                if taken + 1 < n.count {
                    *path.get_mut(d).ok_or(DEEP)? = (at, level, taken + 1);
                    oid = n.child(self.node, taken + 1)?;
                    depth = d + 1;
                    break;
                }
            }
        }
    }

    /// Object `obj`'s records of `kind`, in key order, to `visit` until it returns false (apfs.py's records).
    fn records(&mut self, vol: Volume, obj: u64, kind: u8, visit: &mut Records<'_, D>) -> Result {
        let want = (obj, kind);
        self.scan(vol, want, &mut |disk, k, v| {
            let at = key(k)?;
            if at < want {
                return Ok(true);
            }
            if at > want {
                return Ok(false);
            }
            visit(disk, k, v)
        })
    }

    /// Directory `dir`'s entries, each (name, inode, type) to `visit` until it returns false (apfs.py's entries).
    fn entries(&mut self, vol: Volume, dir: u64, visit: &mut Entries<'_>) -> Result {
        self.records(vol, dir, J_DIR_REC, &mut |_, k, v| {
            // j_drec_hashed_key_t: the name's length in name_len_and_hash's low 10 bits; j_drec_key_t: a u16
            let name = if vol.hashed {
                let len = (le32(k, 8)? & 0x3ff) as usize;
                k.get(12..).and_then(|n| n.get(..len))
            } else {
                let len = usize::from(le16(k, 8)?);
                k.get(10..).and_then(|n| n.get(..len))
            };
            let name = name.ok_or("a directory entry's name past its key")?;
            visit(trim(name), le64(v, 0)?, le16(v, 0x10)? & 0xf)
        })
    }

    /// The directory `name` in directory `dir`: its first entry of that name, as apfs.py's resolve takes it.
    fn subdir(&mut self, vol: Volume, dir: u64, name: &[u8]) -> Result<u64> {
        let mut found = None;
        self.entries(vol, dir, &mut |n, ino, kind| {
            let same = if vol.fold { n.eq_ignore_ascii_case(name) } else { n == name };
            if same {
                found = Some((ino, kind));
            }
            Ok(!same)
        })?;
        match found {
            Some((ino, DT_DIR)) => Ok(ino),
            _ => Err("a directory on the file's path is missing"),
        }
    }

    /// Directory `dir`'s one regular file whose name `matches`; `none` is the error without one or with more.
    fn only(&mut self, vol: Volume, dir: u64, matches: fn(&[u8]) -> bool, none: &'static str) -> Result<u64> {
        let (mut found, mut count) = (None, 0usize);
        self.entries(vol, dir, &mut |n, ino, kind| {
            if matches(n) {
                found = Some((ino, kind));
                count += 1;
            }
            Ok(true)
        })?;
        match found {
            Some((ino, DT_REG)) if count == 1 => Ok(ino),
            _ => Err(none),
        }
    }

    /// Inode `ino`, a regular file: its data stream's id and size (0 without one, as apfs.py's inode) and whether it
    /// is compressed (UF_COMPRESSED: its data in its decmpfs attributes, as macOS's decmpfs takes it).
    fn inode(&mut self, vol: Volume, ino: u64) -> Result<(u64, u64, bool)> {
        let mut found = None;
        self.records(vol, ino, J_INODE, &mut |_, _, v| {
            if le16(v, 0x50)? & S_IFMT != S_IFREG {
                return Err("a file is not a regular file");
            }
            // the extended fields: n headers (type, flags, size), then each one's data 8-byte aligned
            let n = usize::from(le16(v, 0x5c)?);
            let (mut data, mut size) = (0x60 + 4 * n, 0);
            for i in 0..n {
                let ([kind], len) = (bytes::<1>(v, 0x60 + 4 * i)?, le16(v, 0x60 + 4 * i + 2)?);
                if kind == INO_EXT_DSTREAM {
                    size = le64(v, data)?;
                }
                data = data.saturating_add((usize::from(len) + 7) & !7);
            }
            found = Some((le64(v, 0x8)?, size, le32(v, 0x44)? & UF_COMPRESSED != 0));
            Ok(false)
        })?;
        found.ok_or("a directory entry's inode is missing")
    }

    /// Inode `ino`'s extended attribute `name`: its value copied into `buf` if it is embedded, else its stream; None
    /// without it.
    fn xattr(&mut self, vol: Volume, ino: u64, name: &[u8], buf: &mut [u8]) -> Result<Option<Xattr>> {
        let mut found = None;
        self.records(vol, ino, J_XATTR, &mut |_, k, v| {
            let len = usize::from(le16(k, 8)?);
            if trim(k.get(10..).and_then(|n| n.get(..len)).ok_or("an extended attribute's name past its key")?) != name {
                return Ok(true);
            }
            let (flags, len) = (le16(v, 0)?, usize::from(le16(v, 2)?));
            found = Some(if flags & XATTR_DATA_EMBEDDED != 0 {
                let data = v.get(4..).and_then(|d| d.get(..len)).ok_or("an extended attribute's value past its record")?;
                buf.get_mut(..len).ok_or("an extended attribute larger than its buffer")?.copy_from_slice(data);
                Xattr::Embedded(len)
            } else {
                // j_xattr_dstream_t: the stream's id, then its j_dstream_t's size
                Xattr::Stream(le64(v, 4)?, le64(v, 12)?)
            });
            Ok(false)
        })?;
        Ok(found)
    }

    /// Data stream `obj`'s extents in file order, each (file offset, length, partition offset) to `visit` until it
    /// returns false: from offset 0 with no gap and no hole, in whole blocks inside the container (so each one's end
    /// fits a u64).
    fn extents(&mut self, vol: Volume, obj: u64, visit: &mut dyn FnMut(&mut D, u64, u64, u64) -> Result<bool>) -> Result {
        let blocks = self.blocks;
        let mut next = 0u64;
        self.records(vol, obj, J_FILE_EXTENT, &mut |disk, k, v| {
            // j_file_extent_key_t's logical address; j_file_extent_val_t's length (its low 56 bits) and block
            let (at, len, block) = (le64(k, 8)?, le64(v, 0)? & 0x00ff_ffff_ffff_ffff, le64(v, 8)?);
            if at != next || len == 0 || len % BLOCK as u64 != 0 {
                return Err("a file's extents out of order, with a gap, or not in whole blocks");
            }
            if block == 0 || block.checked_add(len / BLOCK as u64).is_none_or(|end| end > blocks) {
                return Err("a file's extent is a hole or outside the container");
            }
            next = at.checked_add(len).ok_or("a file's extents overflow")?;
            // inside the container, whose bytes fit a u64 (open)
            visit(disk, at, len, block * BLOCK as u64)
        })
    }

    /// Data stream `obj`'s bytes from `off` into `buf`.
    fn read_stream(&mut self, vol: Volume, obj: u64, off: u64, buf: &mut [u8]) -> Result {
        let end = off.checked_add(buf.len() as u64).ok_or("a read past the end of a file")?;
        let mut done = off;
        self.extents(vol, obj, &mut |disk, at, len, po| {
            let (a, b) = (off.max(at), end.min(at + len));
            if a < b {
                let to = buf.get_mut((a - off) as usize..(b - off) as usize).ok_or("a read past the end of a file")?;
                disk.read(po + (a - at), to)?;
                done = b;
            }
            Ok(at + len < end)
        })?;
        if done != end {
            return Err("a file's extents end before its size");
        }
        Ok(())
    }
}

/// The caller's scratch as its three blocks.
fn blocks(s: &mut [u8]) -> Result<(&mut [u8; BLOCK], &mut [u8; BLOCK], &mut [u8; BLOCK])> {
    const SHORT: &str = "the APFS reader's scratch is shorter than SCRATCH";
    let (a, s) = s.split_first_chunk_mut::<BLOCK>().ok_or(SHORT)?;
    let (b, s) = s.split_first_chunk_mut::<BLOCK>().ok_or(SHORT)?;
    let (c, _) = s.split_first_chunk_mut::<BLOCK>().ok_or(SHORT)?;
    Ok((a, b, c))
}

/// The xART volume's `.gl`, the one `*.gl` file in its root: its size, and its extents into `out` (each (file offset,
/// length, partition offset), in file order from 0 with no gap, together exactly the file, as disk.rs's Extents holds
/// them) and their count. `scratch` is SCRATCH bytes.
pub(crate) fn find_gl<D: Disk>(
    disk: &mut D,
    scratch: &mut [u8],
    out: &mut [(u64, u64, u64)],
) -> core::result::Result<(u64, usize), &'static str> {
    let (nx, node, _) = blocks(scratch)?;
    let (mut fs, vol) = Fs::open(disk, nx, node, ROLE_XART, "the container has no xART volume")?;
    let ino = fs.only(vol, ROOT_DIR, |n| n.ends_with(b".gl"), "the xART volume's root holds no .gl file, or more than one")?;
    let (stream, size, compressed) = fs.inode(vol, ino)?;
    if size == 0 || compressed {
        return Err("the .gl is empty or compressed");
    }
    let (mut count, mut end) = (0, 0);
    fs.extents(vol, stream, &mut |_, at, len, po| {
        // the last one cut at the file's size
        let len = len.min(size - at);
        *out.get_mut(count).ok_or("the .gl has more extents than the caller's room")? = (at, len, po);
        count += 1;
        end = at + len;
        Ok(end < size)
    })?;
    if end != size {
        return Err("the .gl's extents end before its size");
    }
    Ok((size, count))
}

/// The Hardware volume's factory calibration for the Touch ID sensor, the one `FSCl-<serial>` in CALIBRATION_DIR, into
/// `out`, decompressed if it is compressed: its length. `scratch` is SCRATCH bytes.
pub(crate) fn read_calibration<D: Disk>(
    disk: &mut D,
    scratch: &mut [u8],
    out: &mut [u8],
) -> core::result::Result<usize, &'static str> {
    let (nx, node, win) = blocks(scratch)?;
    let (mut fs, vol) = Fs::open(disk, nx, node, ROLE_HARDWARE, "the container has no Hardware volume")?;
    let mut dir = ROOT_DIR;
    for name in CALIBRATION_DIR {
        dir = fs.subdir(vol, dir, name)?;
    }
    let ino = fs.only(vol, dir, |n| n.starts_with(b"FSCl-"), "com.apple.factorydata holds no FSCl- file, or more than one")?;
    let (stream, size, compressed) = fs.inode(vol, ino)?;
    if compressed {
        return decmpfs(&mut fs, vol, ino, win, out);
    }
    let out = usize::try_from(size).ok().and_then(|n| out.get_mut(..n)).ok_or("the calibration is larger than its buffer")?;
    fs.read_stream(vol, stream, 0, out)?;
    Ok(out.len())
}

/// A compressed file's bytes into `out` (decmpfs, apfs.py's decmpfs): its header's type, LZVN inline after the header
/// (7) or in the resource fork in 64 KiB chunks (8); its length. zlib (3, 4), LZFSE and LZBITMAP are refused: none of
/// the ISC's files is compressed, and core has no inflate.
fn decmpfs<D: Disk>(fs: &mut Fs<'_, D>, vol: Volume, ino: u64, win: &mut [u8; BLOCK], out: &mut [u8]) -> Result<usize> {
    let Some(Xattr::Embedded(len)) = fs.xattr(vol, ino, b"com.apple.decmpfs", win.as_mut_slice())? else {
        return Err("a compressed file without its decmpfs header");
    };
    if win.get(..4) != Some(b"fpmc") {
        return Err("a decmpfs header without its magic");
    }
    let (kind, size) = (le32(win, 4)?, le64(win, 8)?);
    let out = usize::try_from(size).ok().and_then(|n| out.get_mut(..n)).ok_or("the calibration is larger than its buffer")?;
    match kind {
        7 => {
            let data = win.get(16..len).ok_or("a decmpfs header shorter than its fields")?;
            chunk(&mut |i| data.get(i).copied().ok_or("an LZVN chunk read past its end"), out)?;
        }
        8 => {
            let Some(Xattr::Stream(obj, size)) = fs.xattr(vol, ino, b"com.apple.ResourceFork", &mut [])? else {
                return Err("a compressed file without its resource fork's stream");
            };
            // the fork: a table of the chunks' u32 offsets (one more than the chunks), then the chunks
            let mut fork = Window { buf: win, obj, size, at: 0, len: 0 };
            for (k, part) in out.chunks_mut(CHUNK).enumerate() {
                let (from, to) = (fork.le32(fs, vol, 4 * k)? as usize, fork.le32(fs, vol, 4 * k + 4)? as usize);
                let len = to.checked_sub(from).ok_or("a resource fork's chunks out of order")?;
                let mut src = |i| if i < len { fork.byte(fs, vol, from + i) } else { Err("an LZVN chunk read past its end") };
                chunk(&mut src, part)?;
            }
        }
        _ => return Err("a file compressed with other than LZVN: not decoded"),
    }
    Ok(out.len())
}

/// A data stream read a block at a time (a compressed file's resource fork).
struct Window<'w> {
    buf: &'w mut [u8; BLOCK],
    obj: u64,
    size: u64,
    /// The bytes in `buf`: their offset in the stream and their length (0: none yet).
    at: u64,
    len: usize,
}

impl Window<'_> {
    /// The stream's byte at `off`.
    fn byte<D: Disk>(&mut self, fs: &mut Fs<'_, D>, vol: Volume, off: usize) -> Result<u8> {
        let off = off as u64;
        if off >= self.size {
            return Err("a read past the end of a resource fork");
        }
        let at = off - off % BLOCK as u64;
        if self.len == 0 || at != self.at {
            // at most a block, to the stream's end
            let len = (self.size - at).min(BLOCK as u64) as usize;
            fs.read_stream(vol, self.obj, at, self.buf.get_mut(..len).ok_or("a resource fork's window overruns")?)?;
            (self.at, self.len) = (at, len);
        }
        self.buf.get((off - at) as usize).copied().ok_or("a read past the end of a resource fork")
    }

    fn le32<D: Disk>(&mut self, fs: &mut Fs<'_, D>, vol: Volume, off: usize) -> Result<u32> {
        let mut b = [0u8; 4];
        for (i, x) in b.iter_mut().enumerate() {
            *x = self.byte(fs, vol, off + i)?;
        }
        Ok(u32::from_le_bytes(b))
    }
}

/// One decmpfs LZVN chunk into exactly `out`: stored (0x06, then the bytes) or compressed. `src` gives the chunk's
/// bytes by offset and fails past its end.
fn chunk(src: &mut dyn FnMut(usize) -> Result<u8>, out: &mut [u8]) -> Result {
    if src(0)? == 0x06 {
        for (i, o) in out.iter_mut().enumerate() {
            *o = src(i + 1)?;
        }
        return Ok(());
    }
    lzvn(src, out)
}

/// An LZVN stream decoded into exactly `out` (the opcodes of Apple's lzfse, lzvn_decode_base.c; apfs.py's lzvn).
/// `src` gives the stream's bytes by offset and fails past its end; each opcode takes at least one, so the decoding
/// ends. Bytes past `out` are cut, as apfs.py cuts them.
fn lzvn(src: &mut dyn FnMut(usize) -> Result<u8>, out: &mut [u8]) -> Result {
    // the stream's offset, the output's, the last match distance
    let (mut i, mut o, mut d) = (0usize, 0usize, 0usize);
    while o < out.len() {
        let op = src(i)?;
        // the literals, the match's length and the operand bytes after the opcode; `d` set by the distance forms
        let (lit, len, n) = match op {
            // end of stream
            0x06 => break,
            // nop
            0x0e | 0x16 => (0, 0, 0),
            0x1e | 0x26 | 0x2e | 0x36 | 0x3e | 0x70..=0x7f | 0xd0..=0xdf => return Err("LZVN: an undefined opcode"),
            // lrg_m, sml_m: a match at the last distance
            0xf0 => (0, usize::from(src(i + 1)?) + 16, 1),
            0xf1..=0xff => (0, usize::from(op & 0xf), 0),
            // lrg_l, sml_l: literals
            0xe0 => (usize::from(src(i + 1)?) + 16, 0, 1),
            0xe1..=0xef => (usize::from(op & 0xf), 0, 0),
            // med_d: 101LLMMM DDDDDDMM DDDDDDDD
            0xa0..=0xbf => {
                let (b1, b2) = (usize::from(src(i + 1)?), usize::from(src(i + 2)?));
                d = (b2 << 6) | (b1 >> 2);
                (usize::from((op >> 3) & 3), ((usize::from(op & 7) << 2) | (b1 & 3)) + 3, 2)
            }
            // LLMMM111 (lrg_d, a 16-bit distance), LLMMM110 (pre_d, the last), LLMMMDDD DDDDDDDD (sml_d)
            _ => {
                let (lit, len) = (usize::from(op >> 6), usize::from((op >> 3) & 7) + 3);
                match op & 7 {
                    7 => {
                        d = usize::from(src(i + 1)?) | (usize::from(src(i + 2)?) << 8);
                        (lit, len, 2)
                    }
                    6 => (lit, len, 0),
                    _ => {
                        d = (usize::from(op & 7) << 8) | usize::from(src(i + 1)?);
                        (lit, len, 1)
                    }
                }
            }
        };
        i += 1 + n;
        for _ in 0..lit {
            let b = src(i)?;
            i += 1;
            if let Some(x) = out.get_mut(o) {
                *x = b;
                o += 1;
            }
        }
        if len > 0 {
            if d == 0 || d > o {
                return Err("LZVN: a match's distance before the output's start");
            }
            for _ in 0..len {
                // o - d: d is at most o, and o only grows
                let Some(b) = out.get(o - d).copied() else { break };
                let Some(x) = out.get_mut(o) else { break };
                *x = b;
                o += 1;
            }
        }
    }
    if o != out.len() {
        return Err("LZVN: the stream ends before the chunk's size");
    }
    Ok(())
}
