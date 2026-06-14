// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HMAC and HKDF over SHA-1, SHA-256 and SHA-512. SHA-256 backs the PIN KDF;
//! SHA-512 backs the FIDO key-derivation ratchet and the credential key chains;
//! SHA-1 exists only for the YKOATH applet, where HMAC-SHA1 is the
//! protocol-mandated default OTP algorithm (RFC 4226/6238).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{Error, Result};

/// HMAC-SHA1 — the RFC 4226 HOTP/TOTP PRF. Any key length is accepted.
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag);
    out
}

/// HMAC-SHA256. Any key length is accepted.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// HMAC-SHA512. Any key length is accepted.
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time byte-slice equality, for MAC verification — an early-exit
/// compare of a freshly computed (secret) tag against an attacker-controlled
/// value is a timing oracle. Lengths are public, so mismatched lengths may
/// return early.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Barrier so a future compiler can't fold the OR-accumulate into an
    // early-exit branch (CT is verified in disassembly today; this pins it).
    core::hint::black_box(diff) == 0
}

/// HKDF-SHA256 extract-then-expand into `okm`.
/// `okm.len()` must be ≤ 255·32 = 8160.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| Error::BadLength)
}

/// HKDF-SHA512 extract-then-expand into `okm`.
/// `okm.len()` must be ≤ 255·64 = 16320.
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| Error::BadLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut s = std::string::String::new();
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn hmac_sha1_rfc2202_cases() {
        // RFC 2202 §3 case 1.
        let tag = hmac_sha1(&[0x0b; 20], b"Hi There");
        assert_eq!(hex(&tag), "b617318655057264e28bc0b6fb378c8ef146be00");
        // Case 2 — key shorter than the block size.
        let tag = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex(&tag), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0b; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_output_too_long_errors() {
        let mut okm = [0u8; 8161]; // > 255*32
        assert_eq!(
            hkdf_sha256(b"salt", b"ikm", b"info", &mut okm),
            Err(Error::BadLength)
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_case1() {
        let key = [0x0b; 20];
        let tag = hmac_sha512(&key, b"Hi There");
        assert_eq!(
            hex(&tag),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    // No RFC 5869 SHA-512 vectors exist, so check HKDF against its own definition:
    // for L ≤ 64, OKM = HMAC(PRK, info‖0x01) where PRK = HMAC(salt, IKM).
    #[test]
    fn hkdf_sha512_matches_extract_then_expand() {
        let (salt, ikm, info) = (b"salt".as_slice(), b"input key material".as_slice(), b"ctx");
        let mut okm = [0u8; 64];
        hkdf_sha512(salt, ikm, info, &mut okm).unwrap();

        let prk = hmac_sha512(salt, ikm);
        let mut t1_input = std::vec::Vec::from(info.as_slice());
        t1_input.push(0x01);
        assert_eq!(okm, hmac_sha512(&prk, &t1_input));
    }

    #[test]
    fn hkdf_sha512_salt_and_info_change_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha512(b"salt-a", b"ikm", b"info", &mut a).unwrap();
        hkdf_sha512(b"salt-b", b"ikm", b"info", &mut b).unwrap();
        assert_ne!(a, b);
        hkdf_sha512(b"salt-a", b"ikm", b"info-2", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_sha512_output_too_long_errors() {
        let mut okm = [0u8; 16321]; // > 255*64
        assert_eq!(
            hkdf_sha512(b"salt", b"ikm", b"info", &mut okm),
            Err(Error::BadLength)
        );
    }

    #[test]
    fn ct_eq_matches_slice_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd")); // last byte differs
        assert!(!ct_eq(b"xbc", b"abc")); // first byte differs
        assert!(!ct_eq(b"abc", b"ab")); // length mismatch
    }
}
