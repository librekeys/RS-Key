// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Static file table plus the file/metadata API over a [`Storage`] backend.

use heapless::Vec;
use rsk_sdk::error::{Error, Result};

use crate::sealed::{KeyFid, Sealed};
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
    /// Negative cache (paired with [`decided`](Self#structfield.decided)): bit
    /// `fid` set iff the backend is KNOWN to hold a value for `fid`. Lets
    /// `read`/`size` answer "absent" without touching the backend — a backend
    /// `read` of an absent key scans the whole flash partition, so probing a
    /// sparse object range (e.g. the ~25 mostly-empty PIV certificate slots
    /// Yubico Authenticator reads) was O(slots · flash). Set on every write,
    /// cleared on every remove; `scan` seeds it from `for_each_key`.
    ///
    /// A bare clear bit is NOT trusted as "absent": the bulk `for_each_key` can
    /// silently under-count a key after a torn power-cut migration (the reliable
    /// per-key `fetch_item` still recovers it), which would turn a clear bit into
    /// a false-absent — committed data read back as gone. `decided` gates that.
    present: [u8; FID_PRESENT_BYTES],
    /// Authority bit for [`present`](Self#structfield.present): set iff `fid`'s
    /// present/absent state is confirmed. `scan` marks only the keys the bulk
    /// pass actually enumerated; every other FID stays *unknown* until a backend
    /// probe decides it — never a possibly-wrong fast "absent". `fetch_item` is
    /// the source of truth and the cache only memoises it, so a false-absent is
    /// impossible. Cost: the first probe of each absent FID per boot pays one
    /// backend scan, then it is O(1). See [`known_absent`](Self::known_absent).
    decided: [u8; FID_PRESENT_BYTES],
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
            decided: [0u8; FID_PRESENT_BYTES],
            user_authenticated: false,
        }
    }

    /// Recover the backend (e.g. to rebuild the `Fs` — used in tests to model a
    /// reboot).
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Raw present bit (does NOT consult `decided`). Authoritative only for a
    /// FID known present; for the trustworthy absent test use
    /// [`known_absent`](Self::known_absent).
    #[inline]
    fn present_bit(&self, fid: u16) -> bool {
        self.present[(fid >> 3) as usize] & (1u8 << (fid & 7)) != 0
    }

    /// Is `fid`'s present/absent state confirmed (vs. unknown-until-probed)?
    #[inline]
    fn decided_bit(&self, fid: u16) -> bool {
        self.decided[(fid >> 3) as usize] & (1u8 << (fid & 7)) != 0
    }

    /// Trustworthy fast-negative test: true only when `fid` is *confirmed*
    /// absent. An unknown FID returns false so the caller falls through to the
    /// reliable backend (and then caches the result) — this is what prevents a
    /// post-power-cut false-absent. Confirmed-absent stays O(1).
    #[inline]
    fn known_absent(&self, fid: u16) -> bool {
        self.decided_bit(fid) && !self.present_bit(fid)
    }

    /// Cache the backend's authoritative answer for `fid`.
    #[inline]
    fn record(&mut self, fid: u16, present: bool) {
        if present {
            self.mark_present(fid);
        } else {
            self.mark_absent(fid);
        }
    }

    /// Mark `fid` known present (sets the authority bit too).
    #[inline]
    fn mark_present(&mut self, fid: u16) {
        let (i, m) = ((fid >> 3) as usize, 1u8 << (fid & 7));
        self.present[i] |= m;
        self.decided[i] |= m;
    }

    /// Mark `fid` known absent (sets the authority bit, clears present).
    #[inline]
    fn mark_absent(&mut self, fid: u16) {
        let (i, m) = ((fid >> 3) as usize, 1u8 << (fid & 7));
        self.present[i] &= !m;
        self.decided[i] |= m;
    }

    /// Rebuild the dynamic-file set from what's already in storage (run once
    /// after a reboot).
    pub fn scan(&mut self) {
        let table = self.table;
        // Disjoint field borrows so the `for_each_key` closure can update both
        // while `self.storage` drives the pass.
        let dynamic = &mut self.dynamic;
        let present = &mut self.present;
        let decided = &mut self.decided;
        dynamic.clear();
        present.fill(0);
        decided.fill(0);
        self.storage.for_each_key(&mut |fid| {
            // Every enumerated key — static, dynamic, or EF_META — is confirmed
            // present. Keys the bulk pass does NOT yield stay *undecided* (not
            // fast-absent), so a torn-migration under-count can't turn one into a
            // false-absent; it is confirmed against the backend on first access.
            let (i, m) = ((fid >> 3) as usize, 1u8 << (fid & 7));
            present[i] |= m;
            decided[i] |= m;
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
        if self.known_absent(fid) {
            return None; // confirmed absent — skip the backend's full scan
        }
        // Present or unknown: the backend (reliable per-key `fetch_item`) is the
        // source of truth; cache what it says so the next probe is O(1).
        let r = self.storage.read(fid, buf);
        self.record(fid, r.is_some());
        r
    }

    /// Length of the file's contents, or `None` if absent.
    pub fn size(&mut self, fid: u16) -> Option<usize> {
        if self.known_absent(fid) {
            return None;
        }
        let r = self.storage.size(fid);
        self.record(fid, r.is_some());
        r
    }

    /// Whether the file exists with non-empty contents.
    pub fn has_data(&mut self, fid: u16) -> bool {
        if self.known_absent(fid) {
            return false; // confirmed absent — skip the backend's full scan
        }
        let r = self.storage.size(fid);
        self.record(fid, r.is_some());
        r.is_some_and(|n| n > 0)
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
    ///
    /// The backend `remove` (a full-partition scan plus a tombstone write) is
    /// skipped for an absent FID — the present-cache answers in O(1), matching
    /// [`read`](Self::read) / [`has_data`](Self::has_data). Without that guard a
    /// blind delete sweep over many absent slots is O(slots·partition): the FIDO
    /// `authenticatorReset` audit-ring scrub (128 slots) measured ~12 s on
    /// hardware, overrunning host reset timeouts (the FIDO conformance tool gives
    /// a reset 10 s) and wedging the suite.
    ///
    /// The metadata drop and the dynamic-set cleanup, by contrast, run
    /// unconditionally: a file can carry metadata (a [`meta_add`](Self::meta_add)
    /// with no `put`) or a dynamic entry (a [`new_file`](Self::new_file) never
    /// written) without its contents ever being present, so gating either on the
    /// file's present bit would orphan it — a deleted file's metadata would read
    /// back alive. Both stay O(1) when there is nothing to drop: `meta_delete`
    /// has its own EF_META present-cache guard and skips the rewrite when `fid`
    /// had no record.
    ///
    /// Unlike the read paths, the backend `remove` keys off the *raw* present bit
    /// rather than `known_absent`: an UNKNOWN FID is skipped, not confirmed. This
    /// deliberately keeps the cold-boot reset sweep O(1) (confirming 128 unknown
    /// audit slots would re-introduce the multi-second scan). The cost is only
    /// that a delete of a (rare) torn-migration false-absent FID no-ops its own
    /// removal — the file lingers rather than data being lost, and the next read
    /// of it confirms-and-caches it present, after which delete works normally.
    pub fn delete(&mut self, fid: u16) -> Result<()> {
        let _ = self.meta_delete(fid);
        if self.present_bit(fid) {
            self.storage.remove(fid)?;
            self.mark_absent(fid);
        }
        self.dynamic.retain(|&f| f != fid);
        Ok(())
    }

    // ---- typed key-slot API ----
    // Secret key material reaches flash only through these. They delegate to the
    // plaintext primitives, but because a [`KeyFid`] is not a `u16` and
    // [`put_key`](Self::put_key) demands a [`Sealed`] payload, a key slot can be
    // neither written nor read by the generic `put`/`read` — the seal API is the
    // only route in. See [`crate::sealed`].

    /// Store sealed key material at `fid`.
    pub fn put_key(&mut self, fid: KeyFid, sealed: Sealed) -> Result<()> {
        self.put(fid.get(), sealed.as_bytes())
    }

    /// Copy a sealed key blob into `buf`; returns its full length, or `None` if
    /// the slot is absent.
    pub fn read_key(&mut self, fid: KeyFid, buf: &mut [u8]) -> Option<usize> {
        self.read(fid.get(), buf)
    }

    /// Whether the key slot holds non-empty data.
    pub fn has_key(&mut self, fid: KeyFid) -> bool {
        self.has_data(fid.get())
    }

    /// Delete a key slot.
    pub fn delete_key(&mut self, fid: KeyFid) -> Result<()> {
        self.delete(fid.get())
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
        if self.known_absent(EF_META) {
            return None;
        }
        let mut scratch = [0u8; META_MAX];
        let read = self.storage.read(EF_META, &mut scratch);
        self.record(EF_META, read.is_some());
        let n = read?.min(scratch.len());
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
        // Read the existing blob unless EF_META is *confirmed* absent. Treating
        // an UNKNOWN EF_META as empty is the power-cut bug: a torn-migration
        // false-absent would drop every existing record on this rewrite. The
        // reliable backend read recovers the real blob.
        let n = if self.known_absent(EF_META) {
            0
        } else {
            self.storage
                .read(EF_META, &mut scratch)
                .unwrap_or(0)
                .min(scratch.len())
        };
        let mut out = [0u8; META_MAX];
        let w = rebuild_meta(&scratch[..n], fid, Some(data), &mut out)?;
        self.storage.write(EF_META, &out[..w])?;
        self.mark_present(EF_META);
        Ok(())
    }

    /// Remove the metadata for `fid` (clears EF_META once empty).
    pub fn meta_delete(&mut self, fid: u16) -> Result<()> {
        if self.known_absent(EF_META) {
            return Ok(()); // confirmed no meta blob → nothing to drop
        }
        let mut scratch = [0u8; META_MAX];
        let n = match self.storage.read(EF_META, &mut scratch) {
            Some(n) => n.min(scratch.len()),
            None => {
                self.mark_absent(EF_META);
                return Ok(());
            }
        };
        self.mark_present(EF_META);
        let mut out = [0u8; META_MAX];
        let w = rebuild_meta(&scratch[..n], fid, None, &mut out)?;
        if w == n {
            // `fid` had no record (removing one always shrinks the blob), so the
            // rebuild is byte-identical — skip the redundant EF_META rewrite.
            // Keeps a delete sweep over meta-less absent slots write-free.
            Ok(())
        } else if w == 0 {
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
        remove_calls: u32,
        write_calls: u32,
    }
    impl CountingStorage {
        fn new() -> Self {
            Self {
                inner: RamStorage::new(),
                read_calls: 0,
                size_calls: 0,
                remove_calls: 0,
                write_calls: 0,
            }
        }
    }
    impl Storage for CountingStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.read_calls += 1;
            self.inner.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.write_calls += 1;
            self.inner.write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.remove_calls += 1;
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
    fn absent_probe_confirms_once_then_caches() {
        // Tri-state cache: the FIRST probe of an UNKNOWN FID confirms via the
        // backend (one ~160 ms flash scan on device), then memoises the result so
        // every later probe — `read`, `size`, `has_data` — is O(1) and never
        // touches the backend again. Confirming (rather than trusting a bulk-scan
        // clear bit) is what prevents a post-power-cut false-absent; the PIV-tab
        // lag returns only as a one-time-per-boot first probe, then stays fast.
        let mut fs = Fs::new(CountingStorage::new(), TABLE);
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(0xD205, &mut buf), None); // unknown → one confirming read
        // Now decided-absent — answered from the cache, no backend.
        assert_eq!(fs.read(0xD205, &mut buf), None);
        assert_eq!(fs.size(0xD205), None);
        assert!(!fs.has_data(0xD205));
        let st = fs.into_storage();
        assert_eq!(st.read_calls, 1, "exactly one confirming read, then cached");
        assert_eq!(
            st.size_calls, 0,
            "size/has_data answered from the cache after the first read decided it"
        );
    }

    #[test]
    fn confirm_on_miss_recovers_unscanned_key() {
        // A torn-migration false-absent: the backend holds a key the present-cache
        // never learned (the bulk `scan` under-counted it). `read` MUST confirm
        // against the reliable backend, not fast-return None — otherwise committed
        // data reads back lost. Modelled by writing straight to the backend and
        // building an Fs that never scanned it.
        let mut backend = RamStorage::new();
        backend.write(0xCF09, b"resident-cred").unwrap();
        let mut fs = Fs::new(backend, TABLE);
        let mut buf = [0u8; 32];
        assert_eq!(fs.read(0xCF09, &mut buf), Some(13)); // recovered, not false-absent
        assert_eq!(&buf[..13], b"resident-cred");
        // A genuinely absent sibling is confirmed absent and then cached.
        assert_eq!(fs.read(0xCF0A, &mut buf), None);
    }

    #[test]
    fn meta_add_keeps_records_when_ef_meta_unknown() {
        // Bug B at unit scope: EF_META present in the backend but UNKNOWN to the
        // cache (the torn-migration false-absent). A `meta_add` must read the real
        // blob and KEEP existing records — the bug was treating an unknown EF_META
        // as empty and wiping every record on the rewrite.
        let mut fs = fs();
        fs.meta_add(0xB000, b"keep-me").unwrap();
        let backend = fs.into_storage(); // backend now holds EF_META = {B000}
        // Rebuild without scan() → EF_META is unknown (decided clear).
        let mut fs2 = Fs::new(backend, TABLE);
        fs2.meta_add(0xB004, b"new").unwrap();
        assert_eq!(fs2.meta_find(0xB000, &mut [0u8; 16]), Some(7)); // survived
        assert_eq!(fs2.meta_find(0xB004, &mut [0u8; 16]), Some(3));
    }

    #[test]
    fn absent_delete_never_touches_the_backend() {
        // A backend `remove` of an absent FID scans the whole flash partition
        // (and writes a tombstone) on sequential-storage. The present-cache MUST
        // short-circuit it, exactly like read/size/has_data. A blind delete sweep
        // over absent slots is otherwise O(slots·partition): the FIDO reset
        // audit-ring scrub deletes AUDIT_RING_SLOTS(128) slots and measured ~12 s
        // on hardware, overrunning the conformance tool's 10 s reset timeout.
        let mut fs = Fs::new(CountingStorage::new(), TABLE);
        for fid in 0xC110u16..0xC110 + 128 {
            fs.delete(fid).unwrap(); // all absent
        }
        // A present FID still takes the real delete path (proves the guard isn't
        // a blanket skip that would leak data on reset).
        fs.put(0xC110, b"entry").unwrap();
        fs.delete(0xC110).unwrap();
        assert!(!fs.has_data(0xC110));
        let st = fs.into_storage();
        assert_eq!(
            st.remove_calls, 1,
            "only the one present FID may reach the backend remove; \
             absent deletes must be answered by the present-cache"
        );
    }

    #[test]
    fn typed_key_api_roundtrips() {
        // The typed key API (`put_key`/`read_key`/`has_key`/`delete_key`) is the
        // only way to reach a `KeyFid` slot; it must behave exactly like the
        // plaintext path it delegates to.
        let mut fs = fs();
        let slot = KeyFid::new(0xCEFF);
        let mut buf = [0u8; 32];
        // Absent at first.
        assert_eq!(fs.read_key(slot, &mut buf), None);
        assert!(!fs.has_key(slot));
        // Store a (notionally sealed) blob and read it back.
        let blob = b"nonce|ciphertext|tag";
        fs.put_key(slot, Sealed::wrap(blob)).unwrap();
        assert!(fs.has_key(slot));
        assert_eq!(fs.read_key(slot, &mut buf), Some(blob.len()));
        assert_eq!(&buf[..blob.len()], blob);
        // Same bytes underneath — the type is a guard rail, not a separate store.
        assert_eq!(fs.read(slot.get(), &mut buf), Some(blob.len()));
        // Delete clears it.
        fs.delete_key(slot).unwrap();
        assert!(!fs.has_key(slot));
        assert_eq!(fs.read_key(slot, &mut buf), None);
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
    fn delete_drops_meta_even_without_file_data() {
        // Regression (power_cut / fs_ops fuzz): metadata can be attached to a FID
        // that was never `put`. `delete` must still drop that metadata; gating the
        // meta cleanup on the file's own present bit orphaned the record, so a
        // deleted file's metadata read back alive (after a reboot the stale
        // EF_META record reappeared, diverging from the model).
        let mut fs = fs();
        let fid = 0xB001; // metadata only — the file contents are never present
        fs.meta_add(fid, b"orphan").unwrap();
        assert_eq!(fs.meta_find(fid, &mut [0u8; 8]), Some(6));
        assert!(!fs.has_data(fid));
        fs.delete(fid).unwrap();
        assert_eq!(fs.meta_find(fid, &mut [0u8; 8]), None);
        // That was the only record, so EF_META is gone entirely now.
        assert_eq!(fs.size(crate::EF_META), None);
    }

    #[test]
    fn meta_delete_of_absent_record_does_not_rewrite() {
        // Deleting a meta-less FID while EF_META holds other records must not
        // rewrite EF_META: a FIDO-reset sweep deletes many absent slots, and a
        // redundant rewrite each time is flash churn plus a needless torn-write
        // window. The sibling record must survive untouched.
        let mut fs = Fs::new(CountingStorage::new(), TABLE);
        fs.meta_add(0xCF00, b"keep").unwrap(); // exactly one EF_META write
        fs.delete(0xB001).unwrap(); // neither data nor a meta record
        assert_eq!(fs.meta_find(0xCF00, &mut [0u8; 8]), Some(4)); // sibling intact
        let st = fs.into_storage();
        assert_eq!(
            st.write_calls, 1,
            "deleting a meta-less FID must not rewrite EF_META (only the setup write)"
        );
        assert_eq!(st.remove_calls, 0, "absent delete must not hit the backend");
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
