// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! EC signing keys for FIDO credentials: [`P256Key`] (U2F + the attestation
//! cert) and the multi-scheme CTAP2 [`CredKey`]. Each curve signs with its
//! canonical digest; ECDSA nonces are deterministic RFC 6979 where the crate
//! supports it (P-256 / P-384 / secp256k1) and random for P-521 (`p521` 0.13
//! has no deterministic signer). ECDSA signatures are DER-encoded.

use alloc::boxed::Box;

use minicbor::Encoder;
use minicbor::encode::{Error as CborError, Write};
use p256::FieldBytes;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::rand_core;
use zeroize::Zeroize;

use crate::Rng;
use crate::consts::{
    ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_MLDSA44, CURVE_ED25519,
    CURVE_MLDSA44, CURVE_P256, CURVE_P256K1, CURVE_P384, CURVE_P521,
};
use crate::cose::{cose_key_akp, cose_key_ec2_var, cose_key_okp_var};

/// Maximum DER-encoded P-256 ECDSA signature length.
pub const MAX_DER_SIG: usize = 72;
/// Max signature length across all credential schemes — an ML-DSA-44
/// signature; the EC curves top out at 141 (P-521 DER ECDSA).
pub const MAX_SIG_LEN: usize = rsk_crypto::MLDSA44_SIG_LEN; // 2420
/// Bytes the key-derivation ratchet must produce — a P-521 scalar is 66 bytes
/// (the ML-DSA-44 seed needs only the first 32).
pub const RATCHET_LEN: usize = 66;

// P-521 fixed-base comb table (`build.rs`-generated): 16 entries `T[i]`, affine
// `(x, y)` big-endian. `T[0]` is an unused identity sentinel.
include!(concat!(env!("OUT_DIR"), "/gen_comb_p521.rs"));

/// Comb width / bits-per-block — MUST match `build.rs`.
const COMB_W: usize = 4;
const COMB_D: usize = 131;

/// Fixed-base scalar multiplication `k·G` for P-521 via a width-`COMB_W` Lim–Lee
/// comb over [`GEN_COMB`]: `COMB_D` doublings + `COMB_D` mixed additions, ~4× faster
/// than the crate's generic variable-base `mul_by_generator` on the in-order
/// Cortex-M33, and bit-identical to it (KAT-checked in tests). Used for ECDSA
/// signing's `k·G` and the public-key derivation `d·G` (both fixed-base on G).
fn comb_mul(k: &p521::Scalar) -> p521::ProjectivePoint {
    use p521::elliptic_curve::PrimeField;
    use p521::elliptic_curve::sec1::FromEncodedPoint;

    // Reconstruct the table points from the const bytes (once per call; the 15
    // deserializations are negligible beside COMB_D point additions). Index 0 is
    // the identity sentinel, never read (the comb skips a zero window).
    let mut tbl = [p521::AffinePoint::GENERATOR; 1 << COMB_W];
    for (i, (x, y)) in GEN_COMB.iter().enumerate().skip(1) {
        let ep = p521::EncodedPoint::from_affine_coordinates(
            p521::FieldBytes::from_slice(x),
            p521::FieldBytes::from_slice(y),
            false,
        );
        tbl[i] =
            Option::from(p521::AffinePoint::from_encoded_point(&ep)).expect("valid comb point");
    }

    let repr = k.to_repr(); // 66-byte big-endian
    let bit = |n: usize| -> usize {
        if n >= 521 {
            0
        } else {
            ((repr[65 - n / 8] >> (n % 8)) & 1) as usize
        }
    };

    let mut q = p521::ProjectivePoint::IDENTITY;
    for t in (0..COMB_D).rev() {
        q += q; // double
        let mut idx = 0usize;
        for j in 0..COMB_W {
            idx |= bit(j * COMB_D + t) << j;
        }
        if idx != 0 {
            q += tbl[idx]; // mixed add: ProjectivePoint += AffinePoint
        }
    }
    q
}

/// A P-256 signing keypair derived from a 32-byte scalar.
pub struct P256Key {
    signing: SigningKey,
}

impl P256Key {
    /// Build the keypair from a 32-byte big-endian scalar (the key-derivation
    /// ratchet output). Returns `None` if the scalar is out of range `[1, n)` —
    /// the caller treats that as a derivation failure.
    pub fn from_scalar(scalar: &[u8; 32]) -> Option<Self> {
        let fb = FieldBytes::from_slice(scalar);
        SigningKey::from_bytes(fb)
            .ok()
            .map(|signing| Self { signing })
    }

    /// Uncompressed public point as `(x, y)`, each 32 bytes — the COSE key coords.
    pub fn public_xy(&self) -> ([u8; 32], [u8; 32]) {
        let pt = self.signing.verifying_key().to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(pt.x().expect("uncompressed point has x"));
        y.copy_from_slice(pt.y().expect("uncompressed point has y"));
        (x, y)
    }

    /// Deterministic ECDSA-SHA256 over `msg`, DER-encoded into `out`; returns the
    /// signature length. `out` must hold at least [`MAX_DER_SIG`] bytes.
    pub fn sign_der(&self, msg: &[u8], out: &mut [u8]) -> usize {
        let sig: DerSignature = self.signing.sign(msg);
        let bytes = sig.as_bytes();
        out[..bytes.len()].copy_from_slice(bytes);
        bytes.len()
    }
}

/// A multi-scheme CTAP2 credential signing key, selected by the credential's
/// stored `curve`.
pub enum CredKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    // The bare scalar, not a `SigningKey`: building a `SigningKey` derives the
    // public key (a fixed-base mul), wasted for getAssertion which only signs.
    // Both signing's `k·G` and `cose_public`'s `d·G` go through [`comb_mul`].
    P521(p521::NonZeroScalar),
    K256(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    // ~17 KB of fips204 NTT-form keys — HEAP-BOXED, not inline. ML-DSA-44
    // signing (`getAssertion`) drives fips204's rejection-sampling loop, whose
    // stack high-water (~well over 100 KiB on thumbv8m) nearly fills the
    // RP2350's ~222 KiB worker stack on its own. Holding the key inline put
    // those 17 KB on the same frame, right below that call, and tipped it into
    // overflow → a hard wedge (panic-halt, FIDO dark until replug). Boxing moves
    // the key to the firmware heap — idle during a FIDO request, since applet
    // keys are reconstructed per-op — freeing that headroom. fips204 zeroizes
    // the keys on drop; the `Box` adds no `Drop` of its own.
    MlDsa44(Box<rsk_crypto::MlDsa44>),
}

// The SigningKey variants zeroize themselves on drop; the bare P-521 scalar
// doesn't (`NonZeroScalar` has no `Drop`).
impl Drop for CredKey {
    fn drop(&mut self) {
        if let Self::P521(s) = self {
            s.zeroize();
        }
    }
}

impl CredKey {
    /// Build the key for `curve` (a `CURVE_*` id) from the ratchet output
    /// `raw`: read the curve's scalar byte length, masking the P-521 top byte
    /// down to 521 bits. `None` if `raw` is too short, the curve is
    /// unsupported, or the scalar is out of range `[1, n)` (a derivation failure).
    pub fn from_raw(curve: i64, raw: &[u8]) -> Option<Self> {
        match curve {
            c if c == CURVE_P256 as i64 => {
                let mut fb = p256::FieldBytes::clone_from_slice(raw.get(..32)?);
                let key = p256::ecdsa::SigningKey::from_bytes(&fb).ok();
                fb.zeroize();
                Some(Self::P256(key?))
            }
            c if c == CURVE_P384 as i64 => {
                let mut fb = p384::FieldBytes::clone_from_slice(raw.get(..48)?);
                let key = p384::ecdsa::SigningKey::from_bytes(&fb).ok();
                fb.zeroize();
                Some(Self::P384(key?))
            }
            c if c == CURVE_P521 as i64 => {
                use p521::elliptic_curve::PrimeField;
                let mut buf = [0u8; 66];
                buf.copy_from_slice(raw.get(..66)?);
                buf[0] >>= 7; // a P-521 scalar is 521 bits: keep only the top byte's bit
                let mut fb = p521::FieldBytes::clone_from_slice(&buf);
                buf.zeroize();
                let scalar = Option::<p521::Scalar>::from(p521::Scalar::from_repr(fb));
                fb.zeroize();
                Some(Self::P521(Option::from(p521::NonZeroScalar::new(scalar?))?))
            }
            c if c == CURVE_P256K1 as i64 => {
                let mut fb = k256::FieldBytes::clone_from_slice(raw.get(..32)?);
                let key = k256::ecdsa::SigningKey::from_bytes(&fb).ok();
                fb.zeroize();
                Some(Self::K256(key?))
            }
            c if c == CURVE_ED25519 as i64 => {
                // The 32-byte seed is hashed to the scalar internally; the
                // top-byte mask (Ed25519 is a 255-bit field) is part of the
                // credential derivation — changing it changes existing keys.
                let mut seed = [0u8; 32];
                seed.copy_from_slice(raw.get(..32)?);
                seed[0] >>= 1;
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                seed.zeroize();
                Some(Self::Ed25519(key))
            }
            c if c == CURVE_MLDSA44 as i64 => {
                // The ratchet's first 32 bytes are the FIPS 204 keygen seed ξ;
                // expansion is deterministic, so the same credential id always
                // rebuilds the same lattice keypair (as the EC schemes do).
                // Boxed onto the heap so the ~17 KB keypair is off the worker
                // stack before the stack-heavy `sign` runs (see the variant doc).
                let mut xi = [0u8; 32];
                xi.copy_from_slice(raw.get(..32)?);
                let key = Box::new(rsk_crypto::MlDsa44::from_seed(&xi));
                xi.zeroize();
                Some(Self::MlDsa44(key))
            }
            _ => None,
        }
    }

    /// The COSE algorithm id this key signs with.
    pub fn alg(&self) -> i64 {
        match self {
            Self::P256(_) => ALG_ES256,
            Self::P384(_) => ALG_ES384,
            Self::P521(_) => ALG_ES512,
            Self::K256(_) => ALG_ES256K,
            Self::Ed25519(_) => ALG_EDDSA,
            Self::MlDsa44(_) => ALG_MLDSA44,
        }
    }

    /// Sign `msg` (authData ‖ clientDataHash) into `out`; returns the length
    /// (≤ [`MAX_SIG_LEN`]). ECDSA curves emit DER using the curve's canonical
    /// digest: P-256 / P-384 / secp256k1 deterministic RFC 6979; P-521 a random
    /// nonce from `rng`, with `k·G` via the fixed-base [`comb_mul`]. EdDSA
    /// emits the raw 64 bytes; ML-DSA-44 the raw 2420-byte FIPS 204 signature,
    /// hedged with 32 `rng` bytes.
    pub fn sign(&self, msg: &[u8], rng: &mut impl Rng, out: &mut [u8]) -> usize {
        fn put(bytes: &[u8], out: &mut [u8]) -> usize {
            out[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
        }
        match self {
            Self::P256(k) => {
                let s: p256::ecdsa::DerSignature = k.sign(msg);
                put(s.as_bytes(), out)
            }
            Self::P384(k) => {
                let s: p384::ecdsa::DerSignature = k.sign(msg);
                put(s.as_bytes(), out)
            }
            Self::K256(k) => {
                let s: k256::ecdsa::DerSignature = k.sign(msg);
                put(s.as_bytes(), out)
            }
            Self::P521(d) => {
                use p521::elliptic_curve::Field;
                use p521::elliptic_curve::ops::Reduce;
                use p521::elliptic_curve::point::AffineCoordinates;
                use p521::{FieldBytes, Scalar, U576};

                let d: &Scalar = d; // deref-coerce &NonZeroScalar → &Scalar

                // bits2field(SHA-512(msg)): P-521's field (66 B) is wider than the
                // 64-byte hash, so left-pad (no bit truncation) then reduce mod n —
                // exactly what `ecdsa::hazmat` feeds `sign_prehashed`.
                let h = rsk_crypto::sha512(msg);
                let mut zf = FieldBytes::default();
                zf[2..].copy_from_slice(&h);
                let z = <Scalar as Reduce<U576>>::reduce_bytes(&zf);

                // `sign_prehashed`'s body, but with R = k·G via the fixed-base comb.
                loop {
                    let k = Scalar::random(RngAdapter(&mut *rng));
                    let Some(k_inv) = Option::<Scalar>::from(k.invert()) else {
                        continue;
                    };
                    let r = <Scalar as Reduce<U576>>::reduce_bytes(&comb_mul(&k).to_affine().x());
                    let s = k_inv * (z + r * *d);
                    if let Ok(sig) = p521::ecdsa::Signature::from_scalars(r, s) {
                        return put(sig.to_der().as_bytes(), out);
                    }
                }
            }
            Self::Ed25519(k) => {
                // EdDSA is deterministic; the signature is the raw 64 bytes, not DER.
                let s: ed25519_dalek::Signature = k.sign(msg);
                put(&s.to_bytes(), out)
            }
            Self::MlDsa44(k) => {
                // Hedged FIPS 204 signing: 32 fresh RNG bytes per signature.
                let mut rnd = [0u8; 32];
                rng.fill(&mut rnd);
                let n = k.sign(msg, &rnd, out).unwrap_or(0);
                rnd.zeroize();
                n
            }
        }
    }

    /// Encode the COSE EC2 public key (`{1: 2, 3: alg, -1: crv, -2: x, -3: y}`).
    pub fn cose_public<W: Write>(&self, enc: &mut Encoder<W>) -> Result<(), CborError<W::Error>> {
        match self {
            Self::P256(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES256,
                    CURVE_P256,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::P384(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES384,
                    CURVE_P384,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::P521(d) => {
                // Derive the public key d·G with the fixed-base comb (no SigningKey).
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                let p = comb_mul(d).to_affine().to_encoded_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES512,
                    CURVE_P521,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::K256(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES256K,
                    CURVE_P256K1,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::Ed25519(k) => {
                let pk = k.verifying_key().to_bytes();
                cose_key_okp_var(enc, ALG_EDDSA, CURVE_ED25519, &pk)
            }
            Self::MlDsa44(k) => cose_key_akp(enc, ALG_MLDSA44, &k.public_key()),
        }
    }
}

/// Adapts the crate's [`Rng`] to `rand_core` for the one curve (P-521) that needs
/// a random ECDSA nonce. The wrapped source is the device TRNG in firmware.
struct RngAdapter<'a, R: Rng>(&'a mut R);

impl<R: Rng> rand_core::RngCore for RngAdapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dst);
        Ok(())
    }
}
impl<R: Rng> rand_core::CryptoRng for RngAdapter<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::EncodedPoint;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    #[test]
    fn sign_is_deterministic_and_verifies() {
        let scalar = [0x11u8; 32];
        let key = P256Key::from_scalar(&scalar).unwrap();
        let msg = b"authData||clientDataHash";

        let mut a = [0u8; MAX_DER_SIG];
        let mut b = [0u8; MAX_DER_SIG];
        let na = key.sign_der(msg, &mut a);
        let nb = key.sign_der(msg, &mut b);
        assert_eq!(&a[..na], &b[..nb], "RFC 6979 nonce → identical signatures");

        // Reconstruct the public key from the COSE coords and verify.
        let (x, y) = key.public_xy();
        let pt = EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let sig = Signature::from_der(&a[..na]).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn out_of_range_scalar_rejected() {
        // n < this < 2^256: the group order's high bytes are 0xFFFF…, so all-FF
        // is above n and must be rejected.
        assert!(P256Key::from_scalar(&[0xFFu8; 32]).is_none());
        // Zero is not a valid private scalar either.
        assert!(P256Key::from_scalar(&[0u8; 32]).is_none());
    }

    #[test]
    fn distinct_scalars_give_distinct_keys() {
        let k1 = P256Key::from_scalar(&[0x11u8; 32]).unwrap();
        let k2 = P256Key::from_scalar(&[0x22u8; 32]).unwrap();
        assert_ne!(k1.public_xy(), k2.public_xy());
    }

    use crate::consts::{
        ALG_EDDSA, ALG_ES256K, ALG_ES384, ALG_ES512, CURVE_ED25519, CURVE_P256K1, CURVE_P384,
        CURVE_P521,
    };
    use minicbor::encode::write::Cursor;
    use minicbor::{Decoder, Encoder};

    const MSG: &[u8] = b"authData||clientDataHash";

    #[test]
    fn p521_comb_matches_mul_by_generator() {
        use p521::Scalar;
        use p521::elliptic_curve::PrimeField;
        use p521::elliptic_curve::ops::MulByGenerator;
        use p521::elliptic_curve::sec1::ToEncodedPoint;

        // Scalars exercising each 131-bit comb block, its boundaries, and a spread.
        let mut reprs: std::vec::Vec<[u8; 66]> = std::vec::Vec::new();
        reprs.push([0u8; 66]); // 0 → identity
        let mut one = [0u8; 66];
        one[65] = 1;
        reprs.push(one); // 1 → G
        for bitpos in [131usize, 262, 393, 520] {
            let mut r = [0u8; 66];
            r[65 - bitpos / 8] = 1 << (bitpos % 8);
            reprs.push(r); // 2^bitpos → a comb base point / block boundary
        }
        let mut spread = [0u8; 66];
        for (b, byte) in spread.iter_mut().enumerate() {
            *byte = (b as u8).wrapping_mul(37).wrapping_add(1);
        }
        spread[0] = 0; // keep < 2^520 < n so from_repr accepts
        reprs.push(spread);

        for r in reprs {
            let fb = p521::FieldBytes::clone_from_slice(&r);
            let k = Option::<Scalar>::from(Scalar::from_repr(fb)).expect("scalar in range");
            let got = comb_mul(&k).to_affine().to_encoded_point(false);
            let want = p521::ProjectivePoint::mul_by_generator(&k)
                .to_affine()
                .to_encoded_point(false);
            assert_eq!(got, want, "comb mismatch for scalar {r:?}");
        }
    }

    struct SeqRng(u64);
    impl crate::Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    // Encode cose_public and pull the (x, y) byte strings (curve-agnostic shape).
    fn cose_xy(key: &CredKey) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            key.cose_public(&mut e).unwrap();
            e.writer().position()
        };
        let mut d = Decoder::new(&buf[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 5);
        d.u8().unwrap();
        d.u8().unwrap(); // 1: kty 2
        d.u8().unwrap();
        d.i64().unwrap(); // 3: alg
        d.i8().unwrap();
        d.u8().unwrap(); // -1: crv
        d.i8().unwrap();
        let x = d.bytes().unwrap().to_vec(); // -2
        d.i8().unwrap();
        let y = d.bytes().unwrap().to_vec(); // -3
        (x, y)
    }

    #[test]
    fn p384_sign_verifies_under_cose_key() {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let key = CredKey::from_raw(CURVE_P384 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
        assert_eq!(key.alg(), ALG_ES384);
        let mut sig = [0u8; MAX_SIG_LEN];
        let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
        let (x, y) = cose_xy(&key);
        assert_eq!(x.len(), 48);
        let pt = p384::EncodedPoint::from_affine_coordinates(
            p384::FieldBytes::from_slice(&x),
            p384::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
            .unwrap();
    }

    #[test]
    fn p521_sign_verifies_under_cose_key() {
        use p521::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let key = CredKey::from_raw(CURVE_P521 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
        assert_eq!(key.alg(), ALG_ES512);
        let mut sig = [0u8; MAX_SIG_LEN];
        let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
        let (x, y) = cose_xy(&key);
        assert_eq!(x.len(), 66);
        let pt = p521::EncodedPoint::from_affine_coordinates(
            p521::FieldBytes::from_slice(&x),
            p521::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
            .unwrap();
    }

    #[test]
    fn k256_sign_verifies_under_cose_key() {
        use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let key = CredKey::from_raw(CURVE_P256K1 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
        assert_eq!(key.alg(), ALG_ES256K);
        let mut sig = [0u8; MAX_SIG_LEN];
        let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
        let (x, y) = cose_xy(&key);
        assert_eq!(x.len(), 32);
        let pt = k256::EncodedPoint::from_affine_coordinates(
            k256::FieldBytes::from_slice(&x),
            k256::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
            .unwrap();
    }

    #[test]
    fn ed25519_sign_verifies_under_cose_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key = CredKey::from_raw(CURVE_ED25519 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
        assert_eq!(key.alg(), ALG_EDDSA);
        let mut sig = [0u8; MAX_SIG_LEN];
        let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
        assert_eq!(n, 64, "EdDSA signatures are raw 64 bytes");

        // OKP COSE key: {1: 1, 3: EdDSA, -1: 6, -2: pubkey(32)}.
        let mut buf = [0u8; 128];
        let cn = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            key.cose_public(&mut e).unwrap();
            e.writer().position()
        };
        let mut d = Decoder::new(&buf[..cn]);
        assert_eq!(d.map().unwrap().unwrap(), 4);
        d.u8().unwrap();
        assert_eq!(d.u8().unwrap(), 1); // kty OKP
        d.u8().unwrap();
        assert_eq!(d.i64().unwrap(), ALG_EDDSA);
        d.i8().unwrap();
        assert_eq!(d.u8().unwrap(), CURVE_ED25519);
        d.i8().unwrap();
        let pk: [u8; 32] = d.bytes().unwrap().try_into().unwrap();

        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(MSG, &Signature::from_slice(&sig[..n]).unwrap())
            .unwrap();
    }

    // Rough timing of the makeCredential crypto (from_raw + cose_public + sign)
    // per curve. Ignored by default; run with `--release` and
    // `--ignored --nocapture` to compare opt-levels (set CARGO_PROFILE_RELEASE_OPT_LEVEL).
    #[test]
    #[ignore]
    fn bench_register_crypto() {
        use std::time::Instant;
        let raw = [0x11u8; RATCHET_LEN];
        for (name, curve) in [
            ("P256", CURVE_P256),
            ("P384", CURVE_P384),
            ("P521", CURVE_P521),
            ("K256", CURVE_P256K1),
            ("Ed25519", CURVE_ED25519),
        ] {
            let iters = 50u32;
            let mut rng = SeqRng(1);
            let mut sig = [0u8; MAX_SIG_LEN];
            let mut buf = [0u8; 256];
            let t = Instant::now();
            for _ in 0..iters {
                let key = CredKey::from_raw(curve as i64, &raw).unwrap();
                let mut e = Encoder::new(Cursor::new(&mut buf[..]));
                key.cose_public(&mut e).unwrap();
                key.sign(MSG, &mut rng, &mut sig);
            }
            let per = t.elapsed() / iters;
            std::eprintln!("{name}: {per:?}/register-crypto");
        }
    }

    #[test]
    fn p256_credkey_matches_p256key() {
        // CredKey::P256 and P256Key derive the same public point from one scalar.
        let raw = [0x11u8; RATCHET_LEN];
        let ck = CredKey::from_raw(CURVE_P256 as i64, &raw).unwrap();
        assert_eq!(ck.alg(), ALG_ES256);
        let (x, y) = cose_xy(&ck);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&raw[..32]);
        let (px, py) = P256Key::from_scalar(&scalar).unwrap().public_xy();
        assert_eq!(x, px);
        assert_eq!(y, py);
    }

    #[test]
    fn credkey_stays_compact_so_mldsa_key_is_off_the_stack() {
        // The ML-DSA-44 keypair is ~17 KB of fips204 NTT-form keys. Held inline in
        // `CredKey` it rode the worker stack into `sign`, whose fips204
        // rejection-sampling loop already nearly fills the RP2350's ~222 KiB
        // stack — the 17 KB tipped getAssertion into overflow → a hard device
        // wedge. It MUST stay `Box`-ed (heap, idle during a FIDO request). This
        // guard fails loudly if the key regresses back inline: the boxed enum is a
        // few hundred bytes (largest inline variant is Ed25519's expanded
        // `SigningKey`), an inline keypair would be ~16.6 KB.
        let size = core::mem::size_of::<CredKey>();
        assert!(
            size <= 512,
            "CredKey is {size} bytes — is the ML-DSA-44 keypair still Box-ed? \
             An inline fips204 keypair (~16.6 KB) overflows the worker stack in sign()."
        );
    }
}
