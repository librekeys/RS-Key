// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Device master-seed lifecycle: at-rest sealing, format migrations, the
//! soft-lock wrap and first-boot init (seed / counter / large-blob / cert).
//!
//! The seed is stored AES-256-CBC encrypted under the device root key
//! (`derive_kbase`, IV = the serial hash) behind a 1-byte format tag: 0x01 is
//! the device-key-only wrap, 0x11 the same wrap under the OTP-MKEK kbase arm
//! (`migrate_keydev_boot` re-seals 0x01 → 0x11 at boot). The explicit tag is
//! what makes that one-shot re-seal deterministic and crash-safe: CBC has no
//! auth, so trial decryption cannot tell the two kbases apart.
//!
//! 0x03/0x13 are legacy variants with an outer PIN-keyed AEAD; they are never
//! written — a PIN-wrapped seed makes every UP-only operation (an SSH
//! `ed25519-sk` login, any no-PIN assertion) fail after a power cycle until
//! some clientPIN command runs, and the at-rest protection is the kbase itself
//! (silicon-rooted once the OTP key is burnt). Legacy blobs are migrated back
//! to the plain tag at the first successful PIN verify (`migrate_keydev_pin`),
//! the only moment their outer layer is open.

use zeroize::Zeroize;

use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::{Device, Mode, PinKdf, aes_decrypt, aes_encrypt};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::error::{Error, Result};

use crate::Rng;
use crate::cert::build_attestation_cert;
use crate::consts::{
    EF_ATT_KEY, EF_COUNTER, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_LARGEBLOB, LARGEBLOB_INITIAL,
};
use crate::ec::P256Key;

const FORMAT_F1: u8 = 0x01;
const FORMAT_F3: u8 = 0x03;
const FORMAT_F1_OTP: u8 = 0x11;
const FORMAT_F3_OTP: u8 = 0x13;
const KEYDEV_F1_LEN: usize = 33; // format(1) + kbase-encrypted seed(32)
const KEYDEV_F3_LEN: usize = 61; // format(1) + AEAD(nonce 12 + ct 32 + tag 16)

/// `EF_KEY_DEV_ENC` layout: nonce(12) ‖ ChaCha20-Poly1305(seed value, 32) ‖ tag(16).
///
/// The lock wraps the decrypted seed *value*, not the stored file content, so
/// lock/unlock is independent of the at-rest format tag and of the kbase the
/// plain file is sealed under.
pub const LOCK_BLOB_LEN: usize = 12 + 32 + 16;

/// Whether the soft lock is engaged (the wrapped blob is what's on flash).
pub fn lock_engaged<S: Storage>(fs: &mut Fs<S>) -> bool {
    fs.has_key(EF_KEY_DEV_ENC)
}

/// Wrap the seed value under a host-supplied 32-byte lock key (AUT_ENABLE).
pub fn seal_seed_locked(
    rng: &mut impl Rng,
    lock_key: &[u8; 32],
    seed: &[u8; 32],
) -> [u8; LOCK_BLOB_LEN] {
    let mut blob = [0u8; LOCK_BLOB_LEN];
    let (nonce, rest) = blob.split_at_mut(12);
    rng.fill(nonce);
    let (ct, tag) = rest.split_at_mut(32);
    ct.copy_from_slice(seed);
    let nonce12: [u8; 12] = nonce.try_into().unwrap();
    tag.copy_from_slice(&chacha20poly1305_encrypt(lock_key, &nonce12, &[], ct));
    blob
}

/// Unwrap `EF_KEY_DEV_ENC` content with the lock key (vendor UNLOCK). `None` on
/// a wrong key, a tampered blob, or a malformed length.
pub fn open_seed_locked(lock_key: &[u8; 32], blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() != LOCK_BLOB_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(lock_key, &nonce, &[], &mut seed, &tag) {
        Ok(()) => Some(seed),
        Err(_) => {
            seed.zeroize();
            None
        }
    }
}

/// The plain tag this device generation writes (the only format ever written).
fn plain_tag(dev: &Device) -> u8 {
    if dev.otp_key.is_some() {
        FORMAT_F1_OTP
    } else {
        FORMAT_F1
    }
}

/// The derivation context a tag's blob was sealed under: 0x01/0x03 use the
/// pre-OTP arm; 0x11/0x13 need the OTP key (None when it is absent — an OTP-era
/// blob without the OTP key is orphaned and must fail cleanly, never decrypt to
/// CBC garbage).
fn dev_for_tag<'a>(dev: &Device<'a>, tag: u8) -> Option<Device<'a>> {
    match tag {
        FORMAT_F1 | FORMAT_F3 => Some(dev.without_otp()),
        FORMAT_F1_OTP | FORMAT_F3_OTP => dev.otp_key.map(|_| *dev),
        _ => None,
    }
}

/// Read and decrypt the 32-byte device seed. Returns `None` if absent,
/// undecryptable, or still in a legacy PIN-wrapped format (0x03/0x13) — those
/// become loadable again once a successful PIN verify migrates them
/// ([`migrate_keydev_pin`]).
pub fn load_keydev<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_KEY_DEV)
}

/// The org-provisioned FIDO attestation scalar (`EF_ATT_KEY`), sealed exactly
/// like the seed — the tag records which kbase arm wrapped it, so import
/// before or after OTP provisioning both stay loadable.
pub fn load_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_ATT_KEY)
}

pub fn store_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, key: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_ATT_KEY, key)
}

/// Read and decrypt a 32-byte kbase-sealed value (format tags as above).
fn get_sealed32<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Option<[u8; 32]> {
    let mut buf = [0u8; 64];
    let n = fs.read_key(fid, &mut buf)?;
    let seal_dev = dev_for_tag(dev, buf[0]);
    if !(matches!(buf[0], FORMAT_F1 | FORMAT_F1_OTP) && n == KEYDEV_F1_LEN) || seal_dev.is_none() {
        buf.zeroize();
        return None;
    }
    let seal_dev = seal_dev.unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[1..KEYDEV_F1_LEN]);
    let mut kbase = seal_dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let res = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut key);
    kbase.zeroize();
    buf.zeroize();
    match res {
        Ok(()) => Some(key),
        Err(_) => {
            key.zeroize();
            None
        }
    }
}

/// Store `seed` AES-CBC-encrypted under the device root key (tag 0x01, or 0x11
/// once the OTP key is provisioned).
pub fn encrypt_keydev_f1<S: Storage>(dev: &Device, fs: &mut Fs<S>, seed: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_KEY_DEV, seed)
}

/// Store a 32-byte value kbase-sealed behind the current format tag.
fn put_sealed32<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    value: &[u8; 32],
) -> Result<()> {
    let mut kdata = [0u8; KEYDEV_F1_LEN];
    kdata[0] = plain_tag(dev);
    kdata[1..].copy_from_slice(value);
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let res = aes_encrypt(&kbase, &iv, Mode::Cbc, &mut kdata[1..]);
    kbase.zeroize();
    if res.is_err() {
        kdata.zeroize();
        return Err(Error::ExecError);
    }
    let r = fs.put_key(fid, Sealed::wrap(&kdata));
    kdata.zeroize();
    r
}

/// Boot-pass migration: re-seal a pre-OTP plain seed (0x01) under the OTP
/// kbase (0x11). No-op unless `dev` carries the OTP key and the blob is 0x01; a
/// PIN-wrapped (0x03) blob cannot be migrated here — that happens at the first
/// successful PIN verify ([`migrate_keydev_pin`]), the only moment the outer
/// PIN layer is open. Idempotent and crash-safe: the tag flips in the same
/// atomic record write as the re-sealed bytes.
pub fn migrate_keydev_boot<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<()> {
    if dev.otp_key.is_none() {
        return Ok(());
    }
    let mut buf = [0u8; 64];
    let Some(KEYDEV_F1_LEN) = fs.read_key(EF_KEY_DEV, &mut buf) else {
        return Ok(());
    };
    if buf[0] != FORMAT_F1 {
        return Ok(());
    }
    let old = dev.without_otp();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&buf[1..KEYDEV_F1_LEN]);
    buf.zeroize();
    let mut kbase = old.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let res = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut seed);
    kbase.zeroize();
    if res.is_err() {
        seed.zeroize();
        return Err(Error::ExecError);
    }
    let r = encrypt_keydev_f1(dev, fs, &seed);
    seed.zeroize();
    r
}

/// Lazy migration of a legacy PIN-wrapped seed (0x03/0x13) back to the plain
/// kbase-only tag, callable only when a PIN just verified (the outer AEAD key
/// derives from the PIN hash — the only moment that layer is open). A pre-OTP
/// blob on an OTP device is then re-sealed under the OTP kbase on the way
/// (0x03 → 0x11). No-op for plain or unmatchable tags. `pin_hash` is the
/// verified 16-byte PIN hash.
pub fn migrate_keydev_pin<S: Storage>(dev: &Device, fs: &mut Fs<S>, pin_hash: &[u8]) -> Result<()> {
    let mut buf = [0u8; 64];
    let Some(KEYDEV_F3_LEN) = fs.read_key(EF_KEY_DEV, &mut buf) else {
        return Ok(());
    };
    let (seal_dev, plain) = match buf[0] {
        FORMAT_F3 => (dev.without_otp(), FORMAT_F1),
        FORMAT_F3_OTP if dev.otp_key.is_some() => (*dev, FORMAT_F1_OTP),
        _ => return Ok(()),
    };
    // Strip the outer PIN-keyed AEAD; the inner kbase-CBC bytes stay as-is.
    let mut session = seal_dev.pin_derive_session(pin_hash);
    let mut out = [0u8; KEYDEV_F1_LEN];
    out[0] = plain;
    let r = seal_dev.decrypt_with_aad(&session, &buf[1..KEYDEV_F3_LEN], PinKdf::V2, &mut out[1..]);
    session.zeroize();
    buf.zeroize();
    if r.is_err() {
        out.zeroize();
        return Err(Error::ExecError);
    }
    let r = fs.put_key(EF_KEY_DEV, Sealed::wrap(&out));
    out.zeroize();
    r?;
    // A pre-OTP blob on an OTP device still needs its inner layer re-sealed.
    migrate_keydev_boot(dev, fs)
}

/// First-boot init: generate the seed if absent, initialise the signature
/// counter and the default large-blob array, and create the U2F attestation
/// certificate.
///
/// On a soft-locked device (`EF_KEY_DEV` gone, `EF_KEY_DEV_ENC` present) the
/// seed is NOT regenerated — the wrapped blob *is* the seed — and the
/// attestation step is skipped (the cert already exists from before the lock;
/// the seed is unreadable here anyway).
pub fn ensure_seed<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut impl Rng) -> Result<()> {
    let locked = lock_engaged(fs);
    if !fs.has_key(EF_KEY_DEV) && !locked {
        let mut seed = [0u8; 32];
        loop {
            rng.fill(&mut seed);
            if P256Key::from_scalar(&seed).is_some() {
                break;
            }
        }
        let r = encrypt_keydev_f1(dev, fs, &seed);
        seed.zeroize();
        r?;
    }
    if !fs.has_data(EF_COUNTER) {
        fs.put(EF_COUNTER, &[0u8; 4])?;
    }
    if !fs.has_data(EF_LARGEBLOB) {
        fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL)?;
    }
    if !fs.has_data(EF_EE_DEV) && !locked {
        // Self-signed attestation cert over the device key (the seed scalar).
        let mut seed = load_keydev(dev, fs).ok_or(Error::ExecError)?;
        let key = P256Key::from_scalar(&seed).ok_or(Error::ExecError)?;
        seed.zeroize();
        let mut serial = [0u8; 16];
        rng.fill(&mut serial);
        serial[0] &= 0x7F; // keep the INTEGER positive (no leading 0x00 needed)
        let mut buf = [0u8; 512];
        let n = build_attestation_cert(&key, &serial, &mut buf).ok_or(Error::ExecError)?;
        fs.put(EF_EE_DEV, &buf[..n])?;
    }
    Ok(())
}

/// The global signature counter, stored little-endian.
pub fn get_sign_counter<S: Storage>(fs: &mut Fs<S>) -> u32 {
    let mut buf = [0u8; 4];
    match fs.read(EF_COUNTER, &mut buf) {
        Some(4) => u32::from_le_bytes(buf),
        _ => 0,
    }
}

/// Persist `counter+1`; returns the value *before* the bump — the value to
/// report in the current operation.
pub fn bump_sign_counter<S: Storage>(fs: &mut Fs<S>) -> Result<u32> {
    let ctr = get_sign_counter(fs);
    fs.put(EF_COUNTER, &ctr.wrapping_add(1).to_le_bytes())?;
    Ok(ctr)
}

/// Test-only: wrap the stored plain seed in the legacy outer PIN-keyed AEAD
/// (0x01 → 0x03, 0x11 → 0x13) to exercise the migration. The tag arm must
/// match the device generation.
#[cfg(test)]
pub(crate) fn wrap_keydev_legacy<S: Storage>(dev: &Device, fs: &mut Fs<S>, pin_hash: &[u8]) {
    let mut raw = [0u8; KEYDEV_F1_LEN];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_F1_LEN));
    assert_eq!(raw[0], plain_tag(dev));
    let mut out = [0u8; KEYDEV_F3_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F3_OTP
    } else {
        FORMAT_F3
    };
    let session = dev.pin_derive_session(pin_hash);
    dev.encrypt_with_aad(&session, &raw[1..], PinKdf::V2, &[0x24; 12], &mut out[1..])
        .unwrap();
    fs.put(EF_KEY_DEV.get(), &out).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn fs() -> Fs<RamStorage> {
        Fs::new(RamStorage::new(), &[])
    }

    #[test]
    fn seed_roundtrips_through_flash() {
        let d = dev();
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&d, &mut fs, &seed).unwrap();
        // Stored as format(1) + 32 encrypted bytes, not the plaintext seed.
        assert_eq!(fs.size(EF_KEY_DEV.get()), Some(33));
        let mut raw = [0u8; 33];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x01);
        assert_ne!(&raw[1..], &seed);
        // load_keydev recovers it.
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
    }

    #[test]
    fn wrong_device_cannot_decrypt_seed() {
        let mut fs = fs();
        encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
        let other = Device {
            serial_hash: &[0xCD; 32],
            ..dev()
        };
        // Different root key → CBC yields different (wrong) plaintext, not the seed.
        assert_ne!(load_keydev(&other, &mut fs), Some([0x5A; 32]));
    }

    #[test]
    fn legacy_pin_wrapped_seed_unreadable_until_pin_migrates_it() {
        let d = dev();
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];
        encrypt_keydev_f1(&d, &mut fs, &seed).unwrap();
        wrap_keydev_legacy(&d, &mut fs, &pin_hash);
        assert_eq!(fs.size(EF_KEY_DEV.get()), Some(61));
        // The wrapped blob is unreadable (the UP-only failure window)…
        assert_eq!(load_keydev(&d, &mut fs), None);
        // …until a PIN verify unwraps it back to 0x01, permanently.
        migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
        let mut raw = [0u8; 33];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(33));
        assert_eq!(raw[0], 0x01);
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
        // Idempotent.
        migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
    }

    #[test]
    fn migration_with_wrong_pin_fails_and_leaves_blob_intact() {
        let d = dev();
        let mut fs = fs();
        encrypt_keydev_f1(&d, &mut fs, &[0x5A; 32]).unwrap();
        wrap_keydev_legacy(&d, &mut fs, &[0x99u8; 16]);
        assert!(migrate_keydev_pin(&d, &mut fs, &[0x11u8; 16]).is_err());
        let mut raw = [0u8; 61];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
        assert_eq!(raw[0], 0x03);
    }

    #[test]
    fn ensure_seed_is_idempotent() {
        let d = dev();
        let mut fs = fs();
        let mut rng = SeqRng(7);
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        let seed1 = load_keydev(&d, &mut fs).unwrap();
        assert!(fs.has_data(EF_COUNTER));
        assert_eq!(get_sign_counter(&mut fs), 0);
        // A second scan must not regenerate the seed.
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        assert_eq!(load_keydev(&d, &mut fs).unwrap(), seed1);
        assert!(P256Key::from_scalar(&seed1).is_some());
    }

    #[test]
    fn counter_bumps_and_persists() {
        let mut fs = fs();
        fs.put(EF_COUNTER, &[0u8; 4]).unwrap();
        assert_eq!(bump_sign_counter(&mut fs).unwrap(), 0);
        assert_eq!(bump_sign_counter(&mut fs).unwrap(), 1);
        assert_eq!(get_sign_counter(&mut fs), 2);
    }

    #[test]
    fn lock_blob_roundtrips_and_authenticates() {
        let mut rng = SeqRng(3);
        let key = [0x4D; 32];
        let seed = [0x5A; 32];
        let blob = seal_seed_locked(&mut rng, &key, &seed);
        assert_eq!(open_seed_locked(&key, &blob), Some(seed));
        // Wrong key, tampered ciphertext, truncated blob: all refused.
        assert_eq!(open_seed_locked(&[0x4E; 32], &blob), None);
        let mut bad = blob;
        bad[20] ^= 1;
        assert_eq!(open_seed_locked(&key, &bad), None);
        assert_eq!(open_seed_locked(&key, &blob[..LOCK_BLOB_LEN - 1]), None);
    }

    #[test]
    fn ensure_seed_skips_generation_when_locked() {
        // A locked device has only the wrapped blob on flash; a boot pass must
        // not invent a fresh seed next to it (that would fork the identity).
        let d = dev();
        let mut fs = fs();
        let mut rng = SeqRng(9);
        let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
        fs.put(EF_KEY_DEV_ENC.get(), &blob).unwrap();
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        assert!(!fs.has_data(EF_KEY_DEV.get()));
        assert!(fs.has_data(EF_COUNTER)); // the rest of the scan still runs
        assert!(!fs.has_data(EF_EE_DEV)); // cert step skipped (seed unreadable)
    }

    const OTP_KEY: [u8; 32] = [0x77; 32];

    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    #[test]
    fn boot_migration_reseals_plain_seed_to_otp_kbase() {
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap();

        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        let mut raw = [0u8; 33];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x11);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

        // Idempotent: a second pass is a no-op (tag already 0x11).
        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }

    #[test]
    fn boot_migration_without_otp_is_noop() {
        let mut fs = fs();
        encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
        migrate_keydev_boot(&dev(), &mut fs).unwrap();
        let mut raw = [0u8; 33];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x01);
    }

    #[test]
    fn otp_era_seed_fails_cleanly_without_otp_key() {
        // Downgrade scenario: an 0x11 blob read by a no-OTP device must yield a
        // clean None, never CBC garbage masquerading as a seed.
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&otp_dev(), &mut fs, &seed).unwrap();
        let mut raw = [0u8; 33];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x11);
        assert_eq!(load_keydev(&dev(), &mut fs), None);
    }

    #[test]
    fn pre_otp_wrapped_seed_migrates_to_otp_plain_at_verify() {
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];

        // Legacy pre-OTP layout: plain seed, then a PIN set wrapped it (0x03).
        encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap();
        wrap_keydev_legacy(&dev(), &mut fs, &pin_hash);
        let mut raw = [0u8; 61];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x03);

        // The boot pass cannot touch a PIN-wrapped blob.
        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x03);

        // First PIN verify on the OTP build unwraps the outer layer AND re-seals
        // the inner one — straight to a plain 0x11, loadable with no session.
        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(33));
        assert_eq!(raw[0], 0x11);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

        // Idempotent.
        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }

    #[test]
    fn otp_wrapped_seed_migrates_to_plain_at_verify() {
        // A legacy 0x13 blob unwraps to 0x11 at verify; without the OTP key it
        // is left untouched.
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];
        encrypt_keydev_f1(&otp_dev(), &mut fs, &seed).unwrap();
        wrap_keydev_legacy(&otp_dev(), &mut fs, &pin_hash);
        let mut raw = [0u8; 61];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x13);

        // Orphan on a no-OTP build: no-op, no error, still closed.
        migrate_keydev_pin(&dev(), &mut fs, &pin_hash).unwrap();
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], 0x13);
        assert_eq!(load_keydev(&dev(), &mut fs), None);

        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(33));
        assert_eq!(raw[0], 0x11);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }
}
