// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Applet initialisation: creates the absent EFs (DEK, PIN verifiers, default
//! working DOs). Idempotent — every write is guarded by an emptiness check —
//! and run once at boot.

use zeroize::Zeroize;

use rsk_crypto::{Device, PinKdf};
use rsk_fs::{Fs, Sealed, Storage};

use crate::Rng;
use crate::consts::*;
use crate::files::PW_STATUS_DEFAULT;

/// Errors from [`scan_files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A flash write failed.
    Storage,
    /// An AEAD seal failed (a buffer-size invariant was violated).
    Crypto,
}

const FORMAT_V3: u8 = 0x03;
const PIN_FORMAT_V1: u8 = 0x01;
const KDF_DEFAULT: &[u8] = &[0x81, 0x01, 0x00];
const UIF_DEFAULT: &[u8] = &[0x00, 0x20];
const SEX_DEFAULT: &[u8] = &[0x30];
const SIG_COUNT_ZERO: &[u8] = &[0x00, 0x00, 0x00];
const PW_RETRIES_INIT: &[u8] = &[0x01, 3, 3, 3];

fn put<S: Storage>(fs: &mut Fs<S>, fid: u16, data: &[u8]) -> Result<(), Error> {
    fs.put(fid, data).map_err(|_| Error::Storage)
}

/// Build a PIN verifier record `[len, 0x01, verifier(32)]` and store it.
fn put_pin_verifier<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    fid: u16,
    pin: &[u8],
) -> Result<(), Error> {
    let mut rec = [0u8; 34];
    rec[0] = pin.len() as u8;
    rec[1] = PIN_FORMAT_V1;
    rec[2..].copy_from_slice(&dev.pin_derive_verifier(pin));
    let r = put(fs, fid, &rec);
    rec.zeroize();
    r
}

/// Initialise the OpenPGP EFs: the DEK (sealed under the default PINs), the PIN
/// verifiers, and the default working DOs.
pub fn scan_files<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
) -> Result<(), Error> {
    // DEK: generate once when none of the wrapped copies exist.
    let mut reset_dek = false;
    if !fs.has_key(EF_DEK_PW1)
        && !fs.has_key(EF_DEK_RC)
        && !fs.has_key(EF_DEK_PW3)
        && !fs.has_data(EF_DEK)
    {
        let mut random_dek = [0u8; DEK_SIZE];
        rng.fill(&mut random_dek);
        let mut session_pw1 = dev.pin_derive_session(PW1_DEFAULT);
        let mut session_pw3 = dev.pin_derive_session(PW3_DEFAULT);
        let mut def = [0u8; DEK_FILE_SIZE];
        def[0] = FORMAT_V3;
        let mut nonce = [0u8; 12];

        rng.fill(&mut nonce);
        dev.encrypt_with_aad(&session_pw1, &random_dek, PinKdf::V2, &nonce, &mut def[1..])
            .map_err(|_| Error::Crypto)?;
        fs.put_key(EF_DEK_PW1, Sealed::wrap(&def))
            .map_err(|_| Error::Storage)?;

        // RC and PW3 share one blob sealed under the PW3 session.
        rng.fill(&mut nonce);
        dev.encrypt_with_aad(&session_pw3, &random_dek, PinKdf::V2, &nonce, &mut def[1..])
            .map_err(|_| Error::Crypto)?;
        fs.put_key(EF_DEK_RC, Sealed::wrap(&def))
            .map_err(|_| Error::Storage)?;
        fs.put_key(EF_DEK_PW3, Sealed::wrap(&def))
            .map_err(|_| Error::Storage)?;

        random_dek.zeroize();
        session_pw1.zeroize();
        session_pw3.zeroize();
        def.zeroize();
        reset_dek = true;
    }

    if reset_dek || !fs.has_data(EF_PW1) {
        put_pin_verifier(fs, dev, EF_PW1, PW1_DEFAULT)?;
    }
    if reset_dek || !fs.has_data(EF_RC) {
        put_pin_verifier(fs, dev, EF_RC, PW3_DEFAULT)?;
    }
    if reset_dek || !fs.has_data(EF_PW3) {
        put_pin_verifier(fs, dev, EF_PW3, PW3_DEFAULT)?;
    }

    if !fs.has_data(EF_SIG_COUNT) {
        put(fs, EF_SIG_COUNT, SIG_COUNT_ZERO)?;
    }
    if !fs.has_data(EF_PW_PRIV) {
        put(fs, EF_PW_PRIV, PW_STATUS_DEFAULT)?;
    }
    for fid in [EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT] {
        if !fs.has_data(fid) {
            put(fs, fid, UIF_DEFAULT)?;
        }
    }
    if !fs.has_data(EF_KDF) {
        put(fs, EF_KDF, KDF_DEFAULT)?;
    }
    if !fs.has_data(EF_SEX) {
        put(fs, EF_SEX, SEX_DEFAULT)?;
    }
    if !fs.has_data(EF_PW_RETRIES) {
        put(fs, EF_PW_RETRIES, PW_RETRIES_INIT)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    /// Deterministic counter RNG for tests.
    struct CountRng(u8);
    impl Rng for CountRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0x11; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn fresh() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    #[test]
    fn creates_all_default_files() {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

        // DEK files are 77 bytes, format byte 0x03.
        for fid in [EF_DEK_PW1, EF_DEK_RC, EF_DEK_PW3] {
            assert_eq!(fs.size(fid.get()), Some(DEK_FILE_SIZE));
            let mut b = [0u8; 1];
            fs.read(fid.get(), &mut b);
            assert_eq!(b[0], FORMAT_V3);
        }
        // PIN verifiers: [len, 1, verifier(32)].
        let mut rec = [0u8; 34];
        fs.read(EF_PW1, &mut rec);
        assert_eq!(rec[0], 6);
        assert_eq!(rec[1], PIN_FORMAT_V1);
        let mut rec3 = [0u8; 34];
        fs.read(EF_PW3, &mut rec3);
        assert_eq!(rec3[0], 8);

        assert_eq!(fs.size(EF_SIG_COUNT), Some(3));
        let mut pw = [0u8; 7];
        fs.read(EF_PW_PRIV, &mut pw);
        assert_eq!(&pw, &[0x01, 127, 127, 127, 3, 3, 3]);
        assert!(fs.has_data(EF_KDF));
        assert!(fs.has_data(EF_SEX));
        assert!(fs.has_data(EF_PW_RETRIES));
    }

    #[test]
    fn dek_decrypts_under_default_pin() {
        let mut fs = fresh();
        let d = dev();
        scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

        // The wrapped DEK is recoverable with the default PW1 session key.
        let mut blob = [0u8; DEK_FILE_SIZE];
        let n = fs.read(EF_DEK_PW1.get(), &mut blob).unwrap();
        assert_eq!(blob[0], FORMAT_V3);
        let session = d.pin_derive_session(PW1_DEFAULT);
        let mut dek = [0u8; DEK_SIZE];
        let m = d
            .decrypt_with_aad(&session, &blob[1..n], PinKdf::V2, &mut dek)
            .unwrap();
        assert_eq!(m, DEK_SIZE);
        // RC and PW3 are the same blob sealed under PW3 and decrypt to the same DEK.
        let mut blob3 = [0u8; DEK_FILE_SIZE];
        fs.read(EF_DEK_PW3.get(), &mut blob3);
        let session3 = d.pin_derive_session(PW3_DEFAULT);
        let mut dek3 = [0u8; DEK_SIZE];
        d.decrypt_with_aad(&session3, &blob3[1..], PinKdf::V2, &mut dek3)
            .unwrap();
        assert_eq!(dek, dek3);
    }

    #[test]
    fn is_idempotent() {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        let mut first = [0u8; DEK_FILE_SIZE];
        fs.read(EF_DEK_PW1.get(), &mut first);
        // A second run with a different RNG must not rewrite existing files.
        scan_files(&dev(), &mut fs, &mut CountRng(200)).unwrap();
        let mut second = [0u8; DEK_FILE_SIZE];
        fs.read(EF_DEK_PW1.get(), &mut second);
        assert_eq!(first, second);
    }
}
