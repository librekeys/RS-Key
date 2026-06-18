// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Static file table plus the file/metadata API over a [`Storage`] backend.

use heapless::Vec;
use rsk_sdk::error::{Error, Result};

use crate::storage::Storage;
use crate::{EF_META, FILE_EF_TRANSPARENT, FILE_TYPE_WORKING_EF, MAX_DYNAMIC_FILES};

/// Max size of the meta side-store blob.
const META_MAX: usize = 1024;

/// One bit per 16-bit FID: the full `0x0000..=0xFFFF` space as a present/absent
/// bitmap (8 KiB). Backs the fast-negative cache in [`Fs`].
const FID_PRESENT_BYTES: usize = (u16::MAX as usize + 1) / 8;

/// Static descriptor of a known file. File *contents* live in [`Storage`],
/// not here.
#[derive(Clone, Copy, Debug)]
pub struct FileDesc {
    pub fid: u16,
    pub name: Option<&'static [u8]>,
    /// Index of the parent entry in the table.
    pub parent: u8,
    pub file_type: u8,
    pub ef_structure: u8,
    pub acl: [u8; 7],
}

impl FileDesc {
    /// Default descriptor for a runtime-created working EF.
    const fn dynamic(fid: u16) -> Self {
        FileDesc {
            fid,
            name: None,
            parent: 5,
            file_type: FILE_TYPE_WORKING_EF,
            ef_structure: FILE_EF_TRANSPARENT,
            acl: [0u8; 7],
        }
    }
}

/// The file system: a static descriptor table plus the set of dynamic FIDs,
/// over a [`Storage`] backend.
pub struct Fs<S: Storage> {
    storage: S,
    table: &'static [FileDesc],
    dynamic: Vec<u16, MAX_DYNAMIC_FILES>,
    /// Fast-negative cache: bit `fid` is set iff the backend currently stores a
    /// value for `fid`. Lets `read`/`size` answer "absent" without touching the
    /// backend — a backend `read` of an absent key scans the whole flash
    /// partition, so probing a sparse object range (e.g. the ~25 mostly-empty
    /// PIV certificate slots Yubico Authenticator reads) was O(slots · flash).
    /// Mirrors the backend exactly: set on every write, cleared on every
    /// remove, rebuilt from `for_each_key` in [`Fs::scan`]. A fixed bitmap (not
    /// the bounded `dynamic` Vec) so it can never overflow into a false absent.
    present: [u8; FID_PRESENT_BYTES],
    /// Set after user authentication; gates PIN-protected ACL entries.
    pub user_authenticated: bool,
}

impl<S: Storage> Fs<S> {
    pub fn new(storage: S, table: &'static [FileDesc]) -> Self {
        Fs {
            storage,
            table,
            dynamic: Vec::new(),
            present: [0u8; FID_PRESENT_BYTES],
            user_authenticated: false,
        }
    }

    /// Recover the backend (e.g. to rebuild the `Fs` — used in tests to model a
    /// reboot).
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Does the present-cache say `fid` has a stored value? Only authoritative
    /// after [`Fs::scan`] (or when every write went through this `Fs` from an
    /// empty backend), which is the contract — same as the `dynamic` set.
    #[inline]
    fn present_bit(&self, fid: u16) -> bool {
        self.present[(fid >> 3) as usize] & (1u8 << (fid & 7)) != 0
    }

    #[inline]
    fn mark_present(&mut self, fid: u16) {
        self.present[(fid >> 3) as usize] |= 1u8 << (fid & 7);
    }

    #[inline]
    fn mark_absent(&mut self, fid: u16) {
        self.present[(fid >> 3) as usize] &= !(1u8 << (fid & 7));
    }

    /// Rebuild the dynamic-file set from what's already in storage (run once
    /// after a reboot).
    pub fn scan(&mut self) {
        let table = self.table;
        // Disjoint field borrows so the `for_each_key` closure can update both
        // while `self.storage` drives the pass.
        let dynamic = &mut self.dynamic;
        let present = &mut self.present;
        dynamic.clear();
        present.fill(0);
        self.storage.for_each_key(&mut |fid| {
            // Every stored key — static, dynamic, or EF_META — feeds the cache.
            present[(fid >> 3) as usize] |= 1u8 << (fid & 7);
            if fid == EF_META {
                return;
            }
            let is_static = table.iter().any(|d| d.fid == fid);
            if !is_static && !dynamic.contains(&fid) {
                let _ = dynamic.push(fid);
            }
        });
    }

    fn is_static(&self, fid: u16) -> bool {
        self.table.iter().any(|d| d.fid == fid)
    }

    /// Descriptor for `fid`: static entry, or a default dynamic one if the FID
    /// is a known dynamic file. `None` if unknown.
    pub fn descriptor(&self, fid: u16) -> Option<FileDesc> {
        if let Some(d) = self.table.iter().find(|d| d.fid == fid) {
            Some(*d)
        } else if self.dynamic.contains(&fid) {
            Some(FileDesc::dynamic(fid))
        } else {
            None
        }
    }

    /// Is this FID a known file (static or dynamic)?
    pub fn search(&self, fid: u16) -> Option<FileDesc> {
        self.descriptor(fid)
    }

    /// Copy file contents into `buf`; returns the value's full length, or `None`.
    pub fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if !self.present_bit(fid) {
            return None; // absent — skip the backend's full-partition scan
        }
        self.storage.read(fid, buf)
    }

    /// Length of the file's contents, or `None` if absent.
    pub fn size(&mut self, fid: u16) -> Option<usize> {
        if !self.present_bit(fid) {
            return None;
        }
        self.storage.size(fid)
    }

    /// Whether the file exists with non-empty contents.
    pub fn has_data(&mut self, fid: u16) -> bool {
        if !self.present_bit(fid) {
            return false; // absent — skip the backend's full-partition scan
        }
        self.storage.size(fid).is_some_and(|n| n > 0)
    }

    /// Invoke `f` once per live key in the backend, in a single storage pass.
    /// Use this instead of probing a fixed FID range with `read`: a `read` of an
    /// *absent* key rescans the whole flash, so probing 256 slots is O(256·items)
    /// while one `for_each_key` pass is O(items).
    pub fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) {
        self.storage.for_each_key(f);
    }

    /// Register a dynamic working EF (idempotent).
    pub fn new_file(&mut self, fid: u16) -> Result<()> {
        if !self.is_static(fid) && !self.dynamic.contains(&fid) {
            self.dynamic.push(fid).map_err(|_| Error::NoMemory)?;
        }
        Ok(())
    }

    /// Store file contents, registering a dynamic file if new.
    pub fn put(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.storage.write(fid, data)?;
        self.mark_present(fid);
        if !self.is_static(fid) && !self.dynamic.contains(&fid) {
            self.dynamic.push(fid).map_err(|_| Error::NoMemory)?;
        }
        Ok(())
    }

    /// Delete a file: drop its contents, metadata, and any dynamic entry.
    pub fn delete(&mut self, fid: u16) -> Result<()> {
        let _ = self.meta_delete(fid);
        self.storage.remove(fid)?;
        self.mark_absent(fid);
        self.dynamic.retain(|&f| f != fid);
        Ok(())
    }

    /// ACL gate for `op` (an `ACL_OP_*` index).
    pub fn authenticate(&self, fid: u16, op: u8) -> bool {
        let acl = match self.descriptor(fid) {
            Some(d) => d.acl[op as usize],
            None => 0,
        };
        match acl {
            0x00 => true,
            0xff => false,
            0x90 => self.user_authenticated,
            a if a & 0x9f == 0x10 => self.user_authenticated,
            _ => false,
        }
    }

    // ---- meta side-store ----
    // Format: a sequence of records `[fid: u16 BE][len: u16 BE][data; len]`.
    // `read` reports the value's full length, which can exceed our scratch buffer
    // (corrupt/oversized EF_META), so clamp before slicing.

    /// Copy the metadata for `fid` into `out`; returns its full length.
    pub fn meta_find(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if !self.present_bit(EF_META) {
            return None;
        }
        let mut scratch = [0u8; META_MAX];
        let n = self.storage.read(EF_META, &mut scratch)?.min(scratch.len());
        let blob = &scratch[..n];
        let mut i = 0;
        while i + 4 <= blob.len() {
            let rec_fid = u16::from_be_bytes([blob[i], blob[i + 1]]);
            let len = u16::from_be_bytes([blob[i + 2], blob[i + 3]]) as usize;
            let start = i + 4;
            let end = start + len;
            if end > blob.len() {
                break;
            }
            if rec_fid == fid {
                let m = len.min(out.len());
                out[..m].copy_from_slice(&blob[start..start + m]);
                return Some(len);
            }
            i = end;
        }
        None
    }

    /// Insert or replace the metadata for `fid`.
    pub fn meta_add(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        let mut scratch = [0u8; META_MAX];
        let n = if self.present_bit(EF_META) {
            self.storage
                .read(EF_META, &mut scratch)
                .unwrap_or(0)
                .min(scratch.len())
        } else {
            0
        };
        let mut out = [0u8; META_MAX];
        let w = rebuild_meta(&scratch[..n], fid, Some(data), &mut out)?;
        self.storage.write(EF_META, &out[..w])?;
        self.mark_present(EF_META);
        Ok(())
    }

    /// Remove the metadata for `fid` (clears EF_META once empty).
    pub fn meta_delete(&mut self, fid: u16) -> Result<()> {
        if !self.present_bit(EF_META) {
            return Ok(()); // no meta blob → nothing to drop, no backend scan
        }
        let mut scratch = [0u8; META_MAX];
        let n = match self.storage.read(EF_META, &mut scratch) {
            Some(n) => n.min(scratch.len()),
            None => return Ok(()),
        };
        let mut out = [0u8; META_MAX];
        let w = rebuild_meta(&scratch[..n], fid, None, &mut out)?;
        if w == 0 {
            self.storage.remove(EF_META)?;
            self.mark_absent(EF_META);
            Ok(())
        } else {
            self.storage.write(EF_META, &out[..w]) // EF_META stays present
        }
    }
}

/// Copy all meta records except `fid` into `out`, then optionally append a new
/// `fid` record. Returns bytes written.
fn rebuild_meta(blob: &[u8], fid: u16, new: Option<&[u8]>, out: &mut [u8]) -> Result<usize> {
    let mut w = 0usize;
    let mut i = 0usize;
    while i + 4 <= blob.len() {
        let rec_fid = u16::from_be_bytes([blob[i], blob[i + 1]]);
        let len = u16::from_be_bytes([blob[i + 2], blob[i + 3]]) as usize;
        let start = i + 4;
        let end = start + len;
        if end > blob.len() {
            break;
        }
        if rec_fid != fid {
            let rec = &blob[i..end];
            if w + rec.len() > out.len() {
                return Err(Error::NoMemory);
            }
            out[w..w + rec.len()].copy_from_slice(rec);
            w += rec.len();
        }
        i = end;
    }
    if let Some(data) = new {
        if w + 4 + data.len() > out.len() {
            return Err(Error::NoMemory);
        }
        out[w..w + 2].copy_from_slice(&fid.to_be_bytes());
        out[w + 2..w + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        out[w + 4..w + 4 + data.len()].copy_from_slice(data);
        w += 4 + data.len();
    }
    Ok(w)
}

/// Kani proof harnesses (`cargo kani -p rsk-fs`).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `rebuild_meta` walks persisted — possibly corrupt — flash contents.
    /// For ANY blob up to 16 bytes (several records' worth, every truncation),
    /// any record to drop, and any record to append into a too-small output:
    /// no panic, no out-of-bounds write, and the reported length fits.
    #[kani::proof]
    #[kani::unwind(6)]
    fn rebuild_meta_any_blob() {
        const B: usize = 16;
        let blob: [u8; B] = kani::any();
        let bn: usize = kani::any();
        kani::assume(bn <= B);
        let fid: u16 = kani::any();
        let data: [u8; 4] = kani::any();
        let dn: usize = kani::any();
        kani::assume(dn <= 4);
        let with_new: bool = kani::any();
        let new = if with_new { Some(&data[..dn]) } else { None };
        // Smaller than the worst-case rebuild → the NoMemory arms are reachable.
        let mut out = [0u8; 8];
        if let Ok(w) = rebuild_meta(&blob[..bn], fid, new, &mut out) {
            assert!(w <= out.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ram::RamStorage;

    // A tiny static table: an RO file, a PIN-gated file (0x90), and a file whose
    // ACL uses the `& 0x9f == 0x10` auth-required encoding.
    const KEY_DEV: u16 = 0xCC00;
    const PIN: u16 = 0x1080;
    const AUTH10: u16 = 0xCC10;
    static TABLE: &[FileDesc] = &[
        FileDesc {
            fid: KEY_DEV,
            name: None,
            parent: 0,
            file_type: FILE_TYPE_WORKING_EF,
            ef_structure: FILE_EF_TRANSPARENT,
            acl: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00], // ACL_RO: read allowed
        },
        FileDesc {
            fid: PIN,
            name: None,
            parent: 0,
            file_type: FILE_TYPE_WORKING_EF,
            ef_structure: FILE_EF_TRANSPARENT,
            acl: [0x90; 7], // PIN required for every op
        },
        FileDesc {
            fid: AUTH10,
            name: None,
            parent: 0,
            file_type: FILE_TYPE_WORKING_EF,
            ef_structure: FILE_EF_TRANSPARENT,
            acl: [0x10; 7], // auth required via the `& 0x9f == 0x10` arm
        },
    ];

    fn fs() -> Fs<RamStorage> {
        Fs::new(RamStorage::new(), TABLE)
    }

    /// A `Storage` that counts backend probes, proving the present-cache answers
    /// absent lookups without the (on-device, O(flash)) `fetch_item` scan.
    struct CountingStorage {
        inner: RamStorage,
        read_calls: u32,
        size_calls: u32,
    }
    impl CountingStorage {
        fn new() -> Self {
            Self {
                inner: RamStorage::new(),
                read_calls: 0,
                size_calls: 0,
            }
        }
    }
    impl Storage for CountingStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.read_calls += 1;
            self.inner.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.inner.remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.size_calls += 1;
            self.inner.size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) {
            self.inner.for_each_key(f)
        }
    }

    #[test]
    fn put_read_size() {
        let mut fs = fs();
        assert!(!fs.has_data(KEY_DEV));
        fs.put(KEY_DEV, &[1, 2, 3, 4]).unwrap();
        assert_eq!(fs.size(KEY_DEV), Some(4));
        assert!(fs.has_data(KEY_DEV));
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(KEY_DEV, &mut buf), Some(4));
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn dynamic_files_and_reboot() {
        let mut fs = fs();
        // A FID not in the static table becomes a dynamic file on put.
        assert!(fs.search(0xCF01).is_none());
        fs.put(0xCF01, b"cred").unwrap();
        assert!(fs.search(0xCF01).is_some());

        // Model a reboot: rebuild Fs over the same storage and rescan.
        let storage = fs.into_storage();
        let mut fs2 = Fs::new(storage, TABLE);
        assert!(fs2.search(0xCF01).is_none()); // not yet scanned
        fs2.scan();
        assert!(fs2.search(0xCF01).is_some());
        let mut buf = [0u8; 8];
        assert_eq!(fs2.read(0xCF01, &mut buf), Some(4));
        assert_eq!(&buf[..4], b"cred");
    }

    #[test]
    fn delete_removes() {
        let mut fs = fs();
        fs.put(0xCF02, b"x").unwrap();
        assert!(fs.search(0xCF02).is_some());
        fs.delete(0xCF02).unwrap();
        assert!(fs.search(0xCF02).is_none());
        assert!(!fs.has_data(0xCF02));
    }

    #[test]
    fn present_cache_tracks_put_delete_reput() {
        let mut fs = fs();
        let fid = 0xD205; // a PIV-style object FID; absent at first
        let mut buf = [0u8; 8];
        // Absent → fast-negative path, no stale data.
        assert_eq!(fs.read(fid, &mut buf), None);
        assert_eq!(fs.size(fid), None);
        // Put → readable (fails if the write did not mark the FID present).
        fs.put(fid, b"cert").unwrap();
        assert_eq!(fs.read(fid, &mut buf), Some(4));
        assert_eq!(fs.size(fid), Some(4));
        // Delete → absent again.
        fs.delete(fid).unwrap();
        assert_eq!(fs.read(fid, &mut buf), None);
        assert_eq!(fs.size(fid), None);
        // Re-put after delete → readable (catches a clear-then-set cache bug).
        fs.put(fid, b"again").unwrap();
        assert_eq!(fs.read(fid, &mut buf), Some(5));
        assert_eq!(&buf[..5], b"again");
    }

    #[test]
    fn present_cache_rebuilt_by_scan() {
        // The negative cache MUST be rebuilt by scan(), or post-reboot reads of
        // present files would falsely return None — silent data loss.
        let mut fs = fs();
        fs.put(0xD20A, b"sig-cert").unwrap();
        fs.put(0xCF09, b"resident").unwrap();
        let storage = fs.into_storage();
        let mut fs2 = Fs::new(storage, TABLE);
        fs2.scan();
        let mut buf = [0u8; 16];
        assert_eq!(fs2.read(0xD20A, &mut buf), Some(8));
        assert_eq!(&buf[..8], b"sig-cert");
        assert_eq!(fs2.read(0xCF09, &mut buf), Some(8));
        assert_eq!(fs2.read(0xD20B, &mut buf), None); // never-written sibling
    }

    #[test]
    fn absent_probes_never_touch_the_backend() {
        // On device a backend read/size of an absent FID scans the whole flash
        // partition (~160 ms via sequential-storage `fetch_item`). The present
        // cache MUST answer every absent probe — `read`, `size`, AND `has_data`
        // — without the backend. PIV GET METADATA probes ~24 empty key slots, so
        // a missing guard on `has_data` alone cost ~4 s per `ykman piv info` (the
        // Yubico Authenticator PIV-tab lag).
        let mut fs = Fs::new(CountingStorage::new(), TABLE);
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(0xD205, &mut buf), None);
        assert_eq!(fs.size(0xD205), None);
        assert!(!fs.has_data(0xD205));
        let st = fs.into_storage();
        assert_eq!(st.read_calls, 0, "absent read must not probe the backend");
        assert_eq!(
            st.size_calls, 0,
            "absent size/has_data must not probe the backend"
        );
    }

    #[test]
    fn meta_roundtrip() {
        let mut fs = fs();
        let mut out = [0u8; 32];
        assert_eq!(fs.meta_find(0xCF00, &mut out), None);

        fs.meta_add(0xCF00, b"alpha").unwrap();
        fs.meta_add(0xCF01, b"beta").unwrap();
        assert_eq!(fs.meta_find(0xCF00, &mut out), Some(5));
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(fs.meta_find(0xCF01, &mut out), Some(4));
        assert_eq!(&out[..4], b"beta");

        // Replace.
        fs.meta_add(0xCF00, b"ALPHA2").unwrap();
        assert_eq!(fs.meta_find(0xCF00, &mut out), Some(6));
        assert_eq!(&out[..6], b"ALPHA2");

        // Delete.
        fs.meta_delete(0xCF00).unwrap();
        assert_eq!(fs.meta_find(0xCF00, &mut out), None);
        assert_eq!(fs.meta_find(0xCF01, &mut out), Some(4)); // sibling untouched
    }

    #[test]
    fn meta_find_oversized_does_not_panic() {
        let mut fs = fs();
        let big = [0u8; 2048]; // > META_MAX (1024): must clamp, not slice out of range
        fs.put(crate::EF_META, &big).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(fs.meta_find(0xAAAA, &mut out), None);
    }

    #[test]
    fn meta_find_truncates_into_short_out() {
        let mut fs = fs();
        fs.meta_add(0xCF00, b"0123456789").unwrap();
        let mut out = [0u8; 4];
        // Full length reported even though only `out.len()` bytes are copied.
        assert_eq!(fs.meta_find(0xCF00, &mut out), Some(10));
        assert_eq!(&out, b"0123");
    }

    #[test]
    fn meta_add_overflow_is_nomemory() {
        let mut fs = fs();
        // 4-byte header + 1021 bytes overflows META_MAX (1024).
        let big = [0u8; 1021];
        assert_eq!(fs.meta_add(0xCF00, &big), Err(Error::NoMemory));
    }

    #[test]
    fn meta_delete_clears_ef_meta() {
        let mut fs = fs();
        fs.meta_add(0xCF00, b"x").unwrap();
        assert!(fs.size(crate::EF_META).is_some());
        fs.meta_delete(0xCF00).unwrap();
        // Last record gone → the whole EF_META blob is removed.
        assert_eq!(fs.size(crate::EF_META), None);
        assert_eq!(fs.meta_find(0xCF00, &mut [0u8; 8]), None);
    }

    #[test]
    fn delete_drops_meta() {
        let mut fs = fs();
        fs.put(0xCF06, b"data").unwrap();
        fs.meta_add(0xCF06, b"m").unwrap();
        fs.delete(0xCF06).unwrap();
        assert_eq!(fs.meta_find(0xCF06, &mut [0u8; 8]), None);
    }

    #[test]
    fn new_file_then_put() {
        let mut fs = fs();
        fs.new_file(0xCF07).unwrap();
        assert!(fs.search(0xCF07).is_some()); // registered...
        assert!(!fs.has_data(0xCF07)); // ...but empty until written
        fs.put(0xCF07, b"z").unwrap();
        assert!(fs.has_data(0xCF07));
    }

    #[test]
    fn acl_gate() {
        let mut fs = fs();
        // RO file: read allowed, write denied.
        assert!(fs.authenticate(KEY_DEV, crate::ACL_OP_READ_SEARCH));
        assert!(!fs.authenticate(KEY_DEV, crate::ACL_OP_WRITE));
        // PIN file (0x90) and 0x10-encoded file: both denied until authenticated.
        assert!(!fs.authenticate(PIN, crate::ACL_OP_READ_SEARCH));
        assert!(!fs.authenticate(AUTH10, crate::ACL_OP_READ_SEARCH));
        fs.user_authenticated = true;
        assert!(fs.authenticate(PIN, crate::ACL_OP_READ_SEARCH));
        assert!(fs.authenticate(AUTH10, crate::ACL_OP_READ_SEARCH));
        // Unknown/dynamic FID: default-allow (acl all-zero).
        assert!(fs.authenticate(0xDEAD, crate::ACL_OP_WRITE));
    }
}
