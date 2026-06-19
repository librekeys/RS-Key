// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The rescue device key: a secp256k1 keypair for device attestation. A
//! provisioned OTP DEVK is the scalar itself; otherwise the key lives sealed in
//! flash (`EF_DEVCERT_KEY`, AES-256-CBC under `derive_kbase`, IV = the first half
//! of the serial hash), minted on first use.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use rsk_crypto::{Device, Mode, aes_decrypt, aes_encrypt};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use zeroize::Zeroize;

use crate::Rng;

/// The sealed device key. Outside every applet reset scope, like `EF_PHY`.
pub const EF_DEVCERT_KEY: KeyFid = KeyFid::new(0xE0C1);
/// The uploaded device attestation certificate.
pub const EF_DEVCERT: u16 = 0x2F02;

/// Tag marking a blob sealed under the OTP-arm kbase (the FIDO seed's 0x11
/// generation tag). CBC has no authentication, so this tag is the only way to
/// tell the kbase generations apart; a bare 32-byte blob is always the pre-OTP arm.
const TAG_OTP: u8 = 0x11;

/// A provisioned DEVK is the scalar itself (no flash, no derivation); an
/// invalid DEVK scalar fails outright, with no flash fallback. Without a DEVK,
/// unseal the stored key or mint + seal one first.
pub fn load_or_generate<S: Storage>(
    dev: &Device,
    devk: Option<&[u8; 32]>,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
) -> Option<SigningKey> {
    if let Some(devk) = devk {
        return SigningKey::from_bytes(devk.into()).ok();
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);

    let mut buf = [0u8; 33];
    let mut scalar = [0u8; 32];
    let key = match fs.read_key(EF_DEVCERT_KEY, &mut buf) {
        // Bare 32 bytes: sealed under the pre-OTP kbase arm.
        Some(32) => {
            scalar.copy_from_slice(&buf[..32]);
            let mut kbase = dev.without_otp().derive_kbase();
            let r = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut scalar);
            kbase.zeroize();
            if r.is_err() {
                scalar.zeroize();
                return None;
            }
            SigningKey::from_bytes(&scalar.into()).ok()
        }
        // Tagged 33 bytes: sealed under the OTP arm — absent OTP key, fail
        // cleanly rather than decrypting to CBC garbage.
        Some(33) if buf[0] == TAG_OTP => {
            dev.otp_key?;
            scalar.copy_from_slice(&buf[1..33]);
            let mut kbase = dev.derive_kbase();
            let r = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut scalar);
            kbase.zeroize();
            if r.is_err() {
                scalar.zeroize();
                return None;
            }
            SigningKey::from_bytes(&scalar.into()).ok()
        }
        Some(_) => None,
        None => {
            // Draw until the scalar is a valid non-zero field element
            // (overwhelmingly the first draw), then persist it sealed.
            let key = loop {
                rng.fill(&mut scalar);
                if let Ok(k) = SigningKey::from_bytes(&scalar.into()) {
                    break k;
                }
            };
            let mut kbase = dev.derive_kbase();
            let r = aes_encrypt(&kbase, &iv, Mode::Cbc, &mut scalar);
            kbase.zeroize();
            if r.is_err() || put_sealed(dev, fs, &scalar).is_err() {
                scalar.zeroize();
                return None;
            }
            Some(key)
        }
    };
    buf.zeroize();
    scalar.zeroize();
    key
}

/// Write an already-CBC-sealed scalar in the current generation's on-flash form:
/// bare 32 bytes pre-OTP, `[0x11] ‖ ct` once the OTP key roots the kbase.
fn put_sealed<S: Storage>(dev: &Device, fs: &mut Fs<S>, sealed: &[u8; 32]) -> Result<(), ()> {
    if dev.otp_key.is_some() {
        let mut rec = [0u8; 33];
        rec[0] = TAG_OTP;
        rec[1..].copy_from_slice(sealed);
        let r = fs
            .put_key(EF_DEVCERT_KEY, Sealed::wrap(&rec))
            .map(|_| ())
            .map_err(|_| ());
        rec.zeroize();
        r
    } else {
        fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(sealed))
            .map(|_| ())
            .map_err(|_| ())
    }
}

/// Boot-pass migration: re-seal a bare (pre-OTP) keydev blob under the OTP
/// kbase as the tagged 33-byte form. No-op without the OTP key or when already
/// tagged; idempotent (the tag flips in the same atomic record write).
pub fn migrate_kbase<S: Storage>(dev: &Device, fs: &mut Fs<S>) {
    if dev.otp_key.is_none() {
        return;
    }
    let mut buf = [0u8; 33];
    if fs.read_key(EF_DEVCERT_KEY, &mut buf) != Some(32) {
        return;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&buf[..32]);
    let mut kbase_old = dev.without_otp().derive_kbase();
    let dec = aes_decrypt(&kbase_old, &iv, Mode::Cbc, &mut scalar);
    kbase_old.zeroize();
    if dec.is_ok() {
        let mut kbase = dev.derive_kbase();
        let enc = aes_encrypt(&kbase, &iv, Mode::Cbc, &mut scalar);
        kbase.zeroize();
        if enc.is_ok() {
            let _ = put_sealed(dev, fs, &scalar);
        }
    }
    buf.zeroize();
    scalar.zeroize();
}

/// ECDSA over a host-supplied 32-byte digest; returns r || s (64 bytes), with
/// RFC 6979 deterministic nonces.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Option<[u8; 64]> {
    let sig: Signature = key.sign_prehash(digest).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Some(out)
}

/// The uncompressed SEC1 public point (65 bytes), as KEYDEV_SIGN P1=0x02
/// returns it.
pub fn public_uncompressed(key: &SigningKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    let pt = key.verifying_key().to_encoded_point(false);
    out.copy_from_slice(pt.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    struct LcgRng(u64);
    impl Rng for LcgRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    const OTP: [u8; 32] = [0x55; 32];

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP),
            ..dev()
        }
    }

    fn fs() -> Fs<RamStorage> {
        Fs::new(RamStorage::new(), &[])
    }

    #[test]
    fn devk_wins_over_flash_and_is_the_scalar_itself() {
        let mut fs = fs();
        let mut rng = LcgRng(3);
        // Provision a flash key first; the DEVK must shadow it.
        let flash_key = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
        let devk = [0x42u8; 32];
        let key = load_or_generate(&dev(), Some(&devk), &mut fs, &mut rng).unwrap();
        assert_eq!(key.to_bytes().as_slice(), &devk);
        assert_ne!(key.to_bytes(), flash_key.to_bytes());
        // An invalid DEVK scalar fails outright (no flash fallback).
        assert!(load_or_generate(&dev(), Some(&[0u8; 32]), &mut fs, &mut rng).is_none());
    }

    #[test]
    fn flash_keydev_migrates_to_otp_kbase() {
        let mut fs = fs();
        let mut rng = LcgRng(5);
        let key = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
        assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(32));

        // Boot pass re-seals as the tagged 33-byte form; idempotent.
        migrate_kbase(&otp_dev(), &mut fs);
        assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(33));
        migrate_kbase(&otp_dev(), &mut fs);
        assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(33));

        // The OTP device loads the SAME key; a pre-OTP device fails cleanly.
        let migrated = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
        assert_eq!(migrated.to_bytes(), key.to_bytes());
        assert!(load_or_generate(&dev(), None, &mut fs, &mut rng).is_none());
    }

    #[test]
    fn fresh_key_on_otp_device_is_tagged() {
        let mut fs = fs();
        let mut rng = LcgRng(7);
        let key = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
        assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(33));
        let again = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
        assert_eq!(key.to_bytes(), again.to_bytes());
    }
}
