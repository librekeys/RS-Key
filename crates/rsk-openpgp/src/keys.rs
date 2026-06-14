// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Private-key sealing and the asymmetric operations. Keys live in the internal
//! EFs `EF_PK_SIG`/`DEC`/`AUT`, AES-256-CFB-sealed under the random DEK (key =
//! `dek[16..48]`, IV = `dek[0..16]`; the DEK itself is PIN-wrapped, see
//! [`crate::pin`]). EC blobs are `[curve_id] ‖ scalar`; signatures are raw
//! `r ‖ s` (fixed field width), NOT DER.

use alloc::boxed::Box;
use zeroize::Zeroize;

use rsk_crypto::Device;
use rsk_crypto::aes::{aes_decrypt_cfb_256, aes_encrypt_cfb_256};
use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;

use num_bigint_dig::prime::probably_prime_lucas;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Pkcs1v15Encrypt, Pkcs1v15Sign};
use rsk_rsa_asm::{IncrementalSieve, mod_small, passes_strong_mr_base2, self_test};

// Re-exported so the firmware can name the keygen result type without its own
// `rsa` dependency (the dual-core search returns `Box<RsaPrivateKey>`).
pub use rsa::RsaPrivateKey;

use crate::Rng;
use crate::consts::*;
use crate::dobj::{ATTR_CV25519, ATTR_ED25519, ATTR_P256K1, ATTR_P256R1, ATTR_P384R1, ATTR_P521R1};
use crate::pin::{Session, load_dek};

/// Status 0x6A80 (wrong data).
const WRONG_DATA: Sw = Sw::INCORRECT_PARAMS;

/// Largest raw ECDSA signature: P-521 `r ‖ s` = 2×66 bytes.
pub const MAX_EC_SIG: usize = 132;
/// Largest EC public point: P-521 uncompressed `04 ‖ x ‖ y` = 1 + 2×66 bytes.
pub const MAX_EC_POINT: usize = 133;
/// Largest stored EC key blob: `[curve_id] ‖ scalar` (P-521 scalar = 66 bytes).
const MAX_EC_KDATA: usize = 1 + 66;

// ---------------------------------------------------------------- DEK seal ---

/// Unwrap the DEK with the verified PIN session, then AES-256-CFB decrypt
/// `data` in place (key = `dek[16..48]`, IV = `dek[0..16]`).
pub fn dek_decrypt<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    data: &mut [u8],
) -> Result<(), Sw> {
    let (mut key, mut iv) = load_seal(dev, fs, sess)?;
    let r = aes_decrypt_cfb_256(&key, &iv, data);
    key.zeroize();
    iv.zeroize();
    r.map_err(|_| Sw::EXEC_ERROR)
}

/// The encrypting counterpart of [`dek_decrypt`].
pub fn dek_encrypt<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    data: &mut [u8],
) -> Result<(), Sw> {
    let (mut key, mut iv) = load_seal(dev, fs, sess)?;
    let r = aes_encrypt_cfb_256(&key, &iv, data);
    key.zeroize();
    iv.zeroize();
    r.map_err(|_| Sw::EXEC_ERROR)
}

/// Load the DEK and split it into the AES-CFB (key, IV) seal halves.
fn load_seal<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
) -> Result<([u8; 32], [u8; 16]), Sw> {
    let mut dek = [0u8; DEK_SIZE];
    load_dek(dev, fs, sess, &mut dek)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&dek[IV_SIZE..IV_SIZE + 32]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dek[..IV_SIZE]);
    dek.zeroize();
    Ok((key, iv))
}

// ------------------------------------------------------------------ curves ---

/// The supported EC curves. The one-byte id is an internal tag (stored as
/// `kdata[0]`), only ever read back by this firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    P256,
    P384,
    P521,
    K256,
    Ed25519,
    /// Curve25519 ECDH (the decipher key); OpenPGP "Cv25519".
    X25519,
}

impl Curve {
    fn id(self) -> u8 {
        match self {
            Curve::P256 => 3,
            Curve::P384 => 4,
            Curve::P521 => 5,
            Curve::K256 => 12,
            Curve::Ed25519 => 30,
            Curve::X25519 => 31,
        }
    }

    fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            3 => Curve::P256,
            4 => Curve::P384,
            5 => Curve::P521,
            12 => Curve::K256,
            30 => Curve::Ed25519,
            31 => Curve::X25519,
            _ => return None,
        })
    }
}

/// Map a stored algorithm-attribute (`[algo_id ‖ oid]`) to its curve by matching
/// the **OID only**: for a NIST curve the leading id byte is `ECDSA` (0x13) on a
/// signing key but `ECDH` (0x12) on the decipher key, yet both denote the same
/// curve. Unsupported curves (brainpool / X448 / Ed448) return `None`.
pub fn curve_from_attr(attr: &[u8]) -> Option<Curve> {
    let oid = attr.get(1..)?;
    fn oid_of(tmpl: &[u8]) -> &[u8] {
        &tmpl[2..] // template = [tlv_len, algo_id, oid…]
    }
    if oid == oid_of(ATTR_P256R1) {
        Some(Curve::P256)
    } else if oid == oid_of(ATTR_P384R1) {
        Some(Curve::P384)
    } else if oid == oid_of(ATTR_P521R1) {
        Some(Curve::P521)
    } else if oid == oid_of(ATTR_P256K1) {
        Some(Curve::K256)
    } else if oid == oid_of(ATTR_ED25519) {
        Some(Curve::Ed25519)
    } else if oid == oid_of(ATTR_CV25519) {
        Some(Curve::X25519)
    } else {
        None
    }
}

// --------------------------------------------------------------- EC keypair --

/// A reconstructed EC private key, holding the raw (left-padded) scalar / seed.
/// Reconstructs the RustCrypto key on demand for each operation, then drops it.
pub enum PrivKey {
    P256([u8; 32]),
    P384([u8; 48]),
    P521([u8; 66]),
    K256([u8; 32]),
    Ed25519([u8; 32]),
    /// Curve25519 ECDH: the imported scalar as a big-endian MPI (reversed to the
    /// little-endian RFC 7748 form only at agreement time).
    X25519([u8; 32]),
}

impl Drop for PrivKey {
    fn drop(&mut self) {
        match self {
            PrivKey::P256(s) | PrivKey::K256(s) | PrivKey::Ed25519(s) | PrivKey::X25519(s) => {
                s.zeroize()
            }
            PrivKey::P384(s) => s.zeroize(),
            PrivKey::P521(s) => s.zeroize(),
        }
    }
}

/// Left-pad `s` into an `N`-byte big-endian buffer (OpenPGP MPIs drop leading
/// zeros, so a scalar may arrive shorter than the field width). `None` if `s`
/// is longer than `N`.
fn pad<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() > N {
        return None;
    }
    let mut b = [0u8; N];
    b[N - s.len()..].copy_from_slice(s);
    Some(b)
}

impl PrivKey {
    /// Build the key for `curve` from the imported `scalar` (the private key
    /// material; for Ed25519 it is the 32-byte seed).
    pub fn from_scalar(curve: Curve, scalar: &[u8]) -> Option<Self> {
        Some(match curve {
            Curve::P256 => PrivKey::P256(pad::<32>(scalar)?),
            Curve::P384 => PrivKey::P384(pad::<48>(scalar)?),
            Curve::P521 => PrivKey::P521(pad::<66>(scalar)?),
            Curve::K256 => PrivKey::K256(pad::<32>(scalar)?),
            Curve::Ed25519 => PrivKey::Ed25519(pad::<32>(scalar)?),
            Curve::X25519 => PrivKey::X25519(pad::<32>(scalar)?),
        })
    }

    /// Generate a fresh key for `curve` from the TRNG. The Weierstrass scalars
    /// use the RustCrypto uniform sampler; Ed25519/X25519 keys are 32 random
    /// bytes (the seed / clamped scalar), stored big-endian like an import.
    pub fn generate(curve: Curve, rng: &mut dyn Rng) -> Option<Self> {
        // Each `to_bytes()` scalar copy is bound and wiped after `from_scalar`
        // clones it (the `SecretKey` itself zeroizes on drop).
        match curve {
            Curve::P256 => {
                let mut b = p256::SecretKey::random(&mut RngAdapter(rng)).to_bytes();
                let k = Self::from_scalar(curve, b.as_slice());
                b.zeroize();
                k
            }
            Curve::P384 => {
                let mut b = p384::SecretKey::random(&mut RngAdapter(rng)).to_bytes();
                let k = Self::from_scalar(curve, b.as_slice());
                b.zeroize();
                k
            }
            Curve::P521 => {
                let mut b = p521::SecretKey::random(&mut RngAdapter(rng)).to_bytes();
                let k = Self::from_scalar(curve, b.as_slice());
                b.zeroize();
                k
            }
            Curve::K256 => {
                let mut b = k256::SecretKey::random(&mut RngAdapter(rng)).to_bytes();
                let k = Self::from_scalar(curve, b.as_slice());
                b.zeroize();
                k
            }
            Curve::Ed25519 | Curve::X25519 => {
                let mut s = [0u8; 32];
                rng.fill(&mut s);
                let k = Self::from_scalar(curve, &s);
                s.zeroize();
                k
            }
        }
    }

    /// The key's curve. Public for the PIV applet, which reuses [`PrivKey`] with
    /// its own sealing format.
    pub fn curve(&self) -> Curve {
        match self {
            PrivKey::P256(_) => Curve::P256,
            PrivKey::P384(_) => Curve::P384,
            PrivKey::P521(_) => Curve::P521,
            PrivKey::K256(_) => Curve::K256,
            PrivKey::Ed25519(_) => Curve::Ed25519,
            PrivKey::X25519(_) => Curve::X25519,
        }
    }

    /// The raw private scalar / seed. Public for the PIV applet's own sealing
    /// format; treat as key material.
    pub fn scalar(&self) -> &[u8] {
        match self {
            PrivKey::P256(s) | PrivKey::K256(s) | PrivKey::Ed25519(s) | PrivKey::X25519(s) => s,
            PrivKey::P384(s) => s,
            PrivKey::P521(s) => s,
        }
    }

    /// Sign `prehash` (the message digest gpg sends for ECDSA, or the raw message
    /// for EdDSA) into `out` as raw `r ‖ s` (or the 64-byte EdDSA signature);
    /// returns the length. P-256/P-384/secp256k1 sign deterministically
    /// (RFC 6979); P-521 (no deterministic signer in the crate) uses `rng`.
    pub fn sign(&self, prehash: &[u8], rng: &mut dyn Rng, out: &mut [u8]) -> Result<usize, Sw> {
        fn put(b: &[u8], out: &mut [u8]) -> usize {
            out[..b.len()].copy_from_slice(b);
            b.len()
        }
        match self {
            PrivKey::P256(s) => {
                let k = p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let sig: p256::ecdsa::Signature =
                    k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P384(s) => {
                let k = p384::ecdsa::SigningKey::from_bytes(p384::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let sig: p384::ecdsa::Signature =
                    k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::K256(s) => {
                let k = k256::ecdsa::SigningKey::from_bytes(k256::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let sig: k256::ecdsa::Signature =
                    k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P521(s) => {
                let k = p521::ecdsa::SigningKey::from_bytes(p521::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let mut ad = RngAdapter(rng);
                let sig: p521::ecdsa::Signature = k
                    .sign_prehash_with_rng(&mut ad, prehash)
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let b = sig.to_bytes();
                Ok(put(&b[..], out))
            }
            PrivKey::Ed25519(seed) => {
                use ed25519_dalek::Signer;
                let k = ed25519_dalek::SigningKey::from_bytes(seed);
                let sig = k.sign(prehash);
                Ok(put(&sig.to_bytes(), out))
            }
            PrivKey::X25519(_) => Err(Sw::FUNC_NOT_SUPPORTED), // ECDH-only, never signs
        }
    }

    /// The public point for the public-key DO: uncompressed `04 ‖ x ‖ y` for the
    /// Weierstrass curves, the 32-byte compressed point for Ed25519, the 32-byte
    /// little-endian u-coordinate for X25519. Returns the length written to `out`.
    pub fn public_point(&self, out: &mut [u8]) -> Result<usize, Sw> {
        fn put(b: &[u8], out: &mut [u8]) -> usize {
            out[..b.len()].copy_from_slice(b);
            b.len()
        }
        match self {
            PrivKey::P256(s) => {
                let k = p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(
                    k.verifying_key().to_encoded_point(false).as_bytes(),
                    out,
                ))
            }
            PrivKey::P384(s) => {
                let k = p384::ecdsa::SigningKey::from_bytes(p384::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(
                    k.verifying_key().to_encoded_point(false).as_bytes(),
                    out,
                ))
            }
            PrivKey::K256(s) => {
                let k = k256::ecdsa::SigningKey::from_bytes(k256::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                Ok(put(
                    k.verifying_key().to_encoded_point(false).as_bytes(),
                    out,
                ))
            }
            PrivKey::P521(s) => {
                let k = p521::ecdsa::SigningKey::from_bytes(p521::FieldBytes::from_slice(s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                // p521's newtype `verifying_key()` is dead-cfg'd; derive via From.
                let vk = p521::ecdsa::VerifyingKey::from(&k);
                Ok(put(vk.to_encoded_point(false).as_bytes(), out))
            }
            PrivKey::Ed25519(seed) => {
                let k = ed25519_dalek::SigningKey::from_bytes(seed);
                Ok(put(&k.verifying_key().to_bytes(), out))
            }
            PrivKey::X25519(s) => {
                let mut le = *s;
                le.reverse();
                let pk = x25519_dalek::x25519(le, x25519_dalek::X25519_BASEPOINT_BYTES);
                le.zeroize();
                Ok(put(&pk, out))
            }
        }
    }

    /// ECDH: compute the shared secret with the peer's `peer_point`, writing it to
    /// `out` (the OpenPGP DECIPHER result). The Weierstrass curves (P-256/384/521,
    /// secp256k1) parse a SEC1 peer point and return the affine x-coordinate;
    /// X25519/Cv25519 (Montgomery, RFC 7748) is separate. Ed25519 is signing-only.
    pub fn ecdh(&self, peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
        match self {
            PrivKey::P256(s) => ecdh_p256(s, peer_point, out),
            PrivKey::P384(s) => ecdh_p384(s, peer_point, out),
            PrivKey::P521(s) => ecdh_p521(s, peer_point, out),
            PrivKey::K256(s) => ecdh_k256(s, peer_point, out),
            PrivKey::X25519(s) => ecdh_x25519(s, peer_point, out),
            PrivKey::Ed25519(_) => Err(Sw::FUNC_NOT_SUPPORTED),
        }
    }
}

/// P-256 ECDH: peer point parsed as a SEC1 uncompressed point, shared secret =
/// the affine x-coordinate.
fn ecdh_p256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p256::SecretKey::from_bytes(p256::FieldBytes::from_slice(scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p256::EncodedPoint::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-384 ECDH — same SEC1 idiom as [`ecdh_p256`], 48-byte shared x-coordinate.
fn ecdh_p384(scalar: &[u8; 48], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p384::SecretKey::from_bytes(p384::FieldBytes::from_slice(scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p384::EncodedPoint::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p384::PublicKey>::from(p384::PublicKey::from_encoded_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-521 ECDH — 66-byte shared x-coordinate.
fn ecdh_p521(scalar: &[u8; 66], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p521::SecretKey::from_bytes(p521::FieldBytes::from_slice(scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p521::EncodedPoint::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p521::PublicKey>::from(p521::PublicKey::from_encoded_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// secp256k1 ECDH — 32-byte shared x-coordinate.
fn ecdh_k256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = k256::SecretKey::from_bytes(k256::FieldBytes::from_slice(scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = k256::EncodedPoint::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<k256::PublicKey>::from(k256::PublicKey::from_encoded_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// X25519 ECDH (OpenPGP Cv25519). The stored scalar is the big-endian MPI; X25519
/// wants it little-endian (RFC 7748) — reverse it (x25519-dalek clamps). The peer
/// key arrives as the OpenPGP `0x40`-prefixed native point (little-endian
/// u-coordinate); accept it with or without the prefix. The shared secret is the
/// 32-byte little-endian X25519 result.
fn ecdh_x25519(scalar_be: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let u = match peer_point.len() {
        33 if peer_point[0] == 0x40 => &peer_point[1..],
        32 => peer_point,
        _ => return Err(Sw::DATA_INVALID),
    };
    let mut peer = [0u8; 32];
    peer.copy_from_slice(u);
    let mut le = *scalar_be;
    le.reverse();
    let mut shared = x25519_dalek::x25519(le, peer);
    le.zeroize();
    out[..32].copy_from_slice(&shared);
    shared.zeroize();
    Ok(32)
}

// -------------------------------------------------------- store / load / DO --

/// Seal the EC private key under the DEK and write it to `fid`
/// (`EF_PK_SIG`/`DEC`/`AUT`). Blob = `dek_encrypt([curve_id] ‖ scalar)`.
pub fn store_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: u16,
    key: &PrivKey,
) -> Result<(), Sw> {
    let scalar = key.scalar();
    let n = 1 + scalar.len();
    let mut kdata = [0u8; MAX_EC_KDATA];
    kdata[0] = key.curve().id();
    kdata[1..n].copy_from_slice(scalar);
    let r = (|| {
        dek_encrypt(dev, fs, sess, &mut kdata[..n])?;
        fs.put(fid, &kdata[..n]).map_err(|_| Sw::MEMORY_FAILURE)
    })();
    kdata.zeroize();
    r
}

/// Read and unseal the EC key stored at `fid`.
pub fn load_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: u16,
) -> Result<PrivKey, Sw> {
    let mut kdata = [0u8; MAX_EC_KDATA];
    let n = fs.read(fid, &mut kdata).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    if n < 2 {
        return Err(WRONG_DATA);
    }
    let r = (|| {
        dek_decrypt(dev, fs, sess, &mut kdata[..n])?;
        let curve = Curve::from_id(kdata[0]).ok_or(WRONG_DATA)?;
        PrivKey::from_scalar(curve, &kdata[1..n]).ok_or(WRONG_DATA)
    })();
    kdata.zeroize();
    r
}

/// Wrap a public point as the OpenPGP public-key DO `7F49 { 86 <point> }`, with
/// long-form lengths when the point ≥ 128 bytes (P-521). Returns the DO length.
pub fn make_ec_pubkey_do(point: &[u8], out: &mut [u8]) -> usize {
    let plen = point.len();
    let long = plen >= 128;
    let mut p = 0;
    out[p] = 0x7f;
    p += 1;
    out[p] = 0x49;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = (plen + if long { 3 } else { 2 }) as u8;
    p += 1;
    out[p] = 0x86;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = plen as u8;
    p += 1;
    out[p..p + plen].copy_from_slice(point);
    p + plen
}

/// Seal a 32-byte AES key under the DEK and write it to `EF_AES_KEY`. OpenPGP
/// cannot generate symmetric keys directly, so GENERATE mints a fresh AES-256
/// key whenever the DEC keypair is (re)generated.
pub fn store_aes_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    key: &[u8; 32],
) -> Result<(), Sw> {
    let mut kdata = *key;
    let r = (|| {
        dek_encrypt(dev, fs, sess, &mut kdata)?;
        fs.put(EF_AES_KEY, &kdata).map_err(|_| Sw::MEMORY_FAILURE)
    })();
    kdata.zeroize();
    r
}

/// Load + DEK-unseal the symmetric AES key (`EF_AES_KEY`) for the AES PSO
/// operations. Returns the key bytes in a 32-byte buffer plus the real length
/// (16/24/32 → AES-128/192/256); the caller zeroizes the buffer after use.
pub fn load_aes_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
) -> Result<([u8; 32], usize), Sw> {
    let mut kdata = [0u8; 32];
    let n = fs
        .read(EF_AES_KEY, &mut kdata)
        .filter(|&n| n > 0)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    if let Err(e) = dek_decrypt(dev, fs, sess, &mut kdata[..n]) {
        kdata.zeroize();
        return Err(e);
    }
    Ok((kdata, n))
}

// -------------------------------------------------------- signature counter --

/// Zero the PSO:CDS signature counter (on a new SIG key).
pub fn reset_sig_count<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    fs.put(EF_SIG_COUNT, &[0, 0, 0])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Bump the 3-byte big-endian PSO:CDS counter. If the PW-status "PW1 valid for
/// one signature" flag is set (`EF_PW_PRIV[0] == 0`), clears the PW1 session.
pub fn inc_sig_count<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) -> Result<(), Sw> {
    let mut pw = [0u8; 8];
    if fs.read(EF_PW_PRIV, &mut pw).is_some() && pw[0] == 0 {
        sess.has_pw1 = false;
    }
    let mut c = [0u8; 3];
    fs.read(EF_SIG_COUNT, &mut c)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let v = (((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32).wrapping_add(1);
    let q = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    fs.put(EF_SIG_COUNT, &q).map_err(|_| Sw::MEMORY_FAILURE)
}

// ---------------------------------------------------------------------- RSA --
//
// The big-integer arithmetic is the `rsa` crate (heap-backed). The stored blob
// is `P ‖ Q` (each half of `key_size`); on load the exponent is forced to
// 65537 — gpg only ever imports e = 65537.

/// Largest RSA modulus handled (RSA-4096 = 512 bytes).
pub const MAX_RSA_BYTES: usize = 512;
/// Largest stored RSA blob: `P ‖ Q` for RSA-4096.
const MAX_RSA_KDATA: usize = 512;
/// Largest RSA public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }`.
pub const MAX_RSA_PUBDO: usize = 5 + 4 + MAX_RSA_BYTES + 2 + 8;

/// PKCS#1 DigestInfo prefixes (`SEQ { SEQ { OID, NULL }, OCTET STRING }` header,
/// without the trailing hash) for the five hashes `rsa_sign` recognises.
const DI_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const DI_SHA224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
const DI_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DI_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DI_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const DIGESTINFOS: [(&[u8], usize); 5] = [
    (DI_SHA1, 20),
    (DI_SHA224, 28),
    (DI_SHA256, 32),
    (DI_SHA384, 48),
    (DI_SHA512, 64),
];

/// Build the RSA key from the imported exponent / primes (tags 0x91/0x92/0x93).
pub fn rsa_from_pqe(e: &[u8], p: &[u8], q: &[u8]) -> Option<RsaPrivateKey> {
    RsaPrivateKey::from_p_q(
        BigUint::from_bytes_be(p),
        BigUint::from_bytes_be(q),
        BigUint::from_bytes_be(e),
    )
    .ok()
}

/// The RSA public exponent, fixed at 65537 (what `load_rsa_key` assumes).
const RSA_E: u32 = 65_537;

/// The RSA prime search as a *stepper*, so the CCID transport can yield — and
/// send time-extension keepalives — between candidates. Each
/// [`step`](RsaKeygen::step) tests ONE random candidate (a bounded chunk: one
/// `probably_prime`, ~tens of ms on-device), matching the `rsa` crate's keygen:
/// two `nbits/2`-bit primes with the top two bits set and `gcd(e, prime − 1) = 1`,
/// assembled with `RsaPrivateKey::from_p_q`. The primality decision is
/// Baillie-PSW split across backends: the strong Miller-Rabin base-2 half on
/// the KAT-gated asm modexp (ours, differentially tested against the library),
/// the strong Lucas half and key assembly the vetted library routines.
///
/// `step` decomposes into [`try_candidate`](RsaKeygen::try_candidate) (one
/// draw + test, stateless) and [`offer`](RsaKeygen::offer) (the two-prime
/// pool): the firmware runs `try_candidate` on BOTH RP2350 cores — each with
/// its own RNG stream — and funnels every find through one `offer` pool, so
/// the cores race for `p` and `q` and the expected search time roughly halves.
pub struct RsaKeygen {
    half_bytes: usize,
    e: BigUint,
    p: Option<BigUint>,
    /// Result of the asm modexp known-answer test, checked once up front: if the
    /// fast modexp is wrong on this build/silicon, refuse to generate (rather than
    /// emit a weak key). Always true on the host (num-bigint backend).
    asm_ok: bool,
}

// A keygen abandoned between steps still holds the first found prime.
impl Drop for RsaKeygen {
    fn drop(&mut self) {
        if let Some(p) = &mut self.p {
            p.zeroize();
        }
    }
}

/// The outcome of one [`RsaKeygen::step`]. The `Done` key is boxed so the enum
/// stays pointer-sized (it is returned up the call stack each step).
pub enum RsaStep {
    /// Candidate rejected, or the first prime was just found — call `step` again.
    More,
    /// Both primes found and the private key assembled.
    Done(Box<RsaPrivateKey>),
    /// Unusable parameters (unsupported modulus size) or a key-assembly failure.
    Failed,
}

impl RsaKeygen {
    /// Prepare to generate an `nbits`-bit modulus (only byte-aligned half-sizes —
    /// every real OpenPGP size, 2048/3072/4096, qualifies).
    pub fn new(nbits: usize) -> Self {
        RsaKeygen {
            half_bytes: nbits / 16,
            e: BigUint::from(RSA_E),
            p: None,
            asm_ok: self_test(),
        }
    }

    /// Whether this keygen can run at all: the modulus size is supported (the
    /// asm modexp needs the prime length to be a multiple of 32 bytes — every
    /// standard RSA size qualifies) and the modexp known-answer test passed
    /// (a broken fast modexp must never yield a key).
    pub fn usable(&self) -> bool {
        let half = self.half_bytes;
        self.asm_ok && half != 0 && half <= MAX_RSA_BYTES / 2 && half.is_multiple_of(32)
    }

    /// One prime's size in bytes (half the modulus).
    pub fn half_bytes(&self) -> usize {
        self.half_bytes
    }

    /// Draw and test ONE prime candidate of `half_bytes` — the bounded unit of
    /// search work. Stateless (an associated fn), so a second core can run it
    /// concurrently with its own RNG stream. The pipeline is Baillie-PSW split
    /// across backends: the cheap rejections (the small-prime sieve, the
    /// `gcd(e, n−1)` check), then the strong Miller-Rabin base-2 gate on the
    /// KAT-gated asm modexp, then the vetted software strong Lucas test for
    /// the final accept. Admitting a composite would take a simultaneous
    /// failure of both halves — the same combined guarantee
    /// `probably_prime(_, 0)` gives, with the modexp-heavy half on the fast
    /// path. The caller is responsible for the
    /// [`usable`](RsaKeygen::usable) gate.
    ///
    /// `sieve` is a running [`IncrementalSieve`] owned by the caller (one per
    /// core in the dual-core search): each call advances it by one candidate.
    /// A call that lands on a composite, or that reseeds an exhausted window,
    /// returns `None` cheaply; only a sieve survivor pays the modexp + Lucas.
    pub fn try_candidate(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
    ) -> Option<BigUint> {
        match sieve.step() {
            None => {
                // Window exhausted (or never seeded) — draw a fresh random odd
                // top-two-bits start; this call yields no candidate.
                let mut seed = [0u8; MAX_RSA_BYTES / 2];
                rng.fill(&mut seed[..half_bytes]);
                sieve.reseed(half_bytes, &seed[..half_bytes]);
                seed.zeroize();
                return None;
            }
            Some(false) => return None, // composite by a small prime — cheap
            Some(true) => {}            // sieve survivor — run the dear tests
        }
        let n = sieve.candidate();
        // gcd(e, n − 1) == 1  ⇔  n ≢ 1 (mod e), since e is prime.
        if mod_small(n, RSA_E) == 1 {
            return None;
        }
        // The strong Miller-Rabin half of Baillie-PSW, on the asm modexp.
        if !passes_strong_mr_base2(n) {
            return None;
        }
        let cand = BigUint::from_bytes_le(n);
        // The strong Lucas half (vetted library code). Together with the MR
        // gate above this is exactly `probably_prime(_, 0)` — see the
        // `keygen_bpsw_split_matches_library` test.
        if !probably_prime_lucas(&cand) {
            return None;
        }
        Some(cand)
    }

    /// Feed a found prime into the two-prime pool: the first is held, a second
    /// *distinct* one completes the key (a duplicate is rejected and the held
    /// prime kept — the search just continues). Accepts primes found by any
    /// core, in any order.
    pub fn offer(&mut self, mut cand: BigUint) -> RsaStep {
        match self.p.take() {
            None => {
                self.p = Some(cand);
                RsaStep::More
            }
            Some(p) if p == cand => {
                self.p = Some(p);
                cand.zeroize();
                RsaStep::More
            }
            Some(p) => match RsaPrivateKey::from_p_q(p, cand, self.e.clone()) {
                Ok(k) => RsaStep::Done(Box::new(k)),
                Err(_) => RsaStep::Failed,
            },
        }
    }

    /// [`try_candidate`](RsaKeygen::try_candidate), returning the prime as
    /// little-endian bytes in `out` — the inter-core transport format (the
    /// second core ships raw bytes, not bignums, so the zeroize discipline
    /// stays in this crate). `out` must hold `half_bytes`; the candidate's top
    /// bits are set, so a find is always exactly `half_bytes` long.
    pub fn try_candidate_le(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
        out: &mut [u8],
    ) -> Option<usize> {
        let mut p = Self::try_candidate(sieve, rng, half_bytes)?;
        let mut v = p.to_bytes_le();
        p.zeroize();
        let n = v.len();
        out[..n].copy_from_slice(&v);
        v.zeroize();
        Some(n)
    }

    /// [`offer`](RsaKeygen::offer) from little-endian bytes (the inter-core
    /// transport format); scrubs `bytes` after the conversion.
    pub fn offer_le(&mut self, bytes: &mut [u8]) -> RsaStep {
        let cand = BigUint::from_bytes_le(bytes);
        bytes.zeroize();
        self.offer(cand)
    }

    /// Draw and test one prime candidate, feeding any find into the pool — the
    /// single-core step: [`try_candidate`](RsaKeygen::try_candidate) then
    /// [`offer`](RsaKeygen::offer). `sieve` is the caller's running window.
    pub fn step(&mut self, sieve: &mut IncrementalSieve, rng: &mut dyn Rng) -> RsaStep {
        if !self.usable() {
            return RsaStep::Failed;
        }
        match Self::try_candidate(sieve, rng, self.half_bytes) {
            None => RsaStep::More,
            Some(cand) => self.offer(cand),
        }
    }
}

/// Blocking RSA keygen — drives [`RsaKeygen`] to completion on one core. Used
/// by the synchronous `keypair_gen` (host tests, the non-CCID path); on the
/// device the firmware races `try_candidate` on both cores instead.
pub fn generate_rsa(rng: &mut dyn Rng, nbits: usize) -> Result<RsaPrivateKey, Sw> {
    let mut kg = RsaKeygen::new(nbits);
    let mut sieve = IncrementalSieve::new();
    loop {
        match kg.step(&mut sieve, rng) {
            RsaStep::Done(k) => return Ok(*k),
            RsaStep::Failed => return Err(Sw::EXEC_ERROR),
            RsaStep::More => {}
        }
    }
}

/// Seal the RSA key's `P ‖ Q` under the DEK and write it to `fid`.
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: u16,
    key: &RsaPrivateKey,
) -> Result<(), Sw> {
    let primes = key.primes();
    if primes.len() != 2 {
        return Err(Sw::EXEC_ERROR);
    }
    let mut pb = primes[0].to_bytes_be();
    let mut qb = primes[1].to_bytes_be();
    let half = pb.len().max(qb.len());
    let n = 2 * half;
    if n > MAX_RSA_KDATA {
        pb.zeroize();
        qb.zeroize();
        return Err(Sw::WRONG_LENGTH);
    }
    let mut kdata = [0u8; MAX_RSA_KDATA];
    kdata[half - pb.len()..half].copy_from_slice(&pb);
    kdata[n - qb.len()..n].copy_from_slice(&qb);
    pb.zeroize();
    qb.zeroize();
    let r = (|| {
        dek_encrypt(dev, fs, sess, &mut kdata[..n])?;
        fs.put(fid, &kdata[..n]).map_err(|_| Sw::MEMORY_FAILURE)
    })();
    kdata.zeroize();
    r
}

/// Read and unseal the RSA key at `fid`, rebuilding it from `P ‖ Q` with
/// `E = 65537`.
pub fn load_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: u16,
) -> Result<RsaPrivateKey, Sw> {
    let mut kdata = [0u8; MAX_RSA_KDATA];
    let n = fs.read(fid, &mut kdata).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    if n < 2 || n % 2 != 0 {
        kdata.zeroize();
        return Err(WRONG_DATA);
    }
    let res = (|| {
        dek_decrypt(dev, fs, sess, &mut kdata[..n])?;
        let half = n / 2;
        let p = BigUint::from_bytes_be(&kdata[..half]);
        let q = BigUint::from_bytes_be(&kdata[half..n]);
        RsaPrivateKey::from_p_q(p, q, BigUint::from(65_537u32)).map_err(|_| WRONG_DATA)
    })();
    kdata.zeroize();
    res
}

/// Build the public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }` (modulus
/// tag 0x81 with a 2-byte length, exponent tag 0x82 with a 1-byte one).
pub fn make_rsa_response(key: &RsaPrivateKey, out: &mut [u8]) -> usize {
    let nb = key.n().to_bytes_be();
    let eb = key.e().to_bytes_be();
    let mut p = 0;
    out[p] = 0x7f;
    out[p + 1] = 0x49;
    out[p + 2] = 0x82; // 2-byte outer length, back-patched below
    p += 5;
    let inner = p;
    out[p] = 0x81;
    out[p + 1] = 0x82;
    out[p + 2..p + 4].copy_from_slice(&(nb.len() as u16).to_be_bytes());
    p += 4;
    out[p..p + nb.len()].copy_from_slice(&nb);
    p += nb.len();
    out[p] = 0x82;
    out[p + 1] = eb.len() as u8;
    p += 2;
    out[p..p + eb.len()].copy_from_slice(&eb);
    p += eb.len();
    out[3..5].copy_from_slice(&((p - inner) as u16).to_be_bytes());
    p
}

/// Find the recognised DigestInfo prefix + hash for a canonical PKCS#1 DigestInfo
/// (`SEQ { SEQ { OID, NULL }, OCTET STRING }`). gpg always sends the canonical
/// form, so a prefix + exact-length match identifies it without a full DER walk.
fn match_digestinfo(data: &[u8]) -> Option<(&'static [u8], &[u8])> {
    for (prefix, hlen) in DIGESTINFOS {
        if data.len() == prefix.len() + hlen && data.starts_with(prefix) {
            return Some((prefix, &data[prefix.len()..]));
        }
    }
    None
}

/// Largest DigestInfo `rsa_sign` builds: 19-byte prefix (SHA-512) + 64-byte hash.
pub const MAX_RSA_DIGESTINFO: usize = 19 + 64;

/// Decide what PKCS#1 v1.5 should sign: write the canonical DigestInfo
/// (`prefix ‖ hash`) for a recognised DigestInfo or a bare hash whose length
/// names the algorithm into `em`, returning its length; `None` means neither (the
/// raw private-op fallback). Pure (no key / modexp), so the `openpgp_rsa_sign`
/// fuzz target exercises the parser + buffer construction at full speed.
pub fn rsa_sign_em(data: &[u8], em: &mut [u8; MAX_RSA_DIGESTINFO]) -> Option<usize> {
    let (prefix, hash): (&[u8], &[u8]) = if let Some(di) = match_digestinfo(data) {
        di
    } else {
        match data.len() {
            20 => (DI_SHA1, data),
            28 => (DI_SHA224, data),
            32 => (DI_SHA256, data),
            48 => (DI_SHA384, data),
            64 => (DI_SHA512, data),
            _ => return None,
        }
    };
    let dlen = prefix.len() + hash.len();
    em[..prefix.len()].copy_from_slice(prefix);
    em[prefix.len()..dlen].copy_from_slice(hash);
    Some(dlen)
}

/// PKCS#1 v1.5 over the supplied data. If it is a DigestInfo (or a bare hash
/// whose length names the algorithm), sign that digest; otherwise fall back to
/// the raw private operation.
pub fn rsa_sign(
    key: &RsaPrivateKey,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut em = [0u8; MAX_RSA_DIGESTINFO];
    let Some(dlen) = rsa_sign_em(data, &mut em) else {
        return rsa_raw(key, data, out, rng);
    };
    let sig = key
        .sign_with_rng(
            &mut RngAdapter(rng),
            Pkcs1v15Sign::new_unprefixed(),
            &em[..dlen],
        )
        .map_err(|_| Sw::EXEC_ERROR)?;
    out[..sig.len()].copy_from_slice(&sig);
    Ok(sig.len())
}

/// Run the raw RSA private operation `m^d mod n` (no padding scheme). gpg never
/// reaches this — it always sends a DigestInfo — but the operation is
/// base-blinded `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so even a
/// non-conformant caller cannot turn `num-bigint-dig`'s variable-time
/// exponentiation into a Marvin-style timing oracle on the private exponent.
fn rsa_raw(
    key: &RsaPrivateKey,
    data: &[u8],
    out: &mut [u8],
    rng: &mut dyn Rng,
) -> Result<usize, Sw> {
    use num_bigint_dig::ModInverse;
    let key_size = key.size();
    if data.len() > key_size {
        return Err(WRONG_DATA);
    }
    let (n, e, d) = (key.n(), key.e(), key.d());
    let m = BigUint::from_bytes_be(data);
    // Fresh blinding factor r, invertible mod n (retry on the negligible chance
    // r shares a factor with n).
    let (r, r_inv) = loop {
        let mut rb = [0u8; MAX_RSA_BYTES];
        rng.fill(&mut rb[..key_size]);
        let cand = BigUint::from_bytes_be(&rb[..key_size]) % n;
        if let Some(inv) = (&cand).mod_inverse(n).and_then(|i| i.to_biguint()) {
            break (cand, inv);
        }
    };
    let blinded = (&m * r.modpow(e, n)) % n;
    let res = (blinded.modpow(d, n) * r_inv) % n;
    let rb = res.to_bytes_be();
    if rb.len() > key_size {
        return Err(Sw::EXEC_ERROR);
    }
    let off = key_size - rb.len();
    out[..off].fill(0);
    out[off..key_size].copy_from_slice(&rb);
    Ok(key_size)
}

/// PSO:DECIPHER for RSA: strip the leading OpenPGP padding-indicator byte, then
/// PKCS#1 v1.5 decrypt exactly `key_size` bytes of ciphertext (blinded). `data`
/// is the raw command data field (`apdu.data`).
pub fn rsa_decipher(
    key: &RsaPrivateKey,
    rng: &mut dyn Rng,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let key_size = key.size();
    let ct = data.get(1..1 + key_size).ok_or(WRONG_DATA)?;
    let mut pt = key
        .decrypt_blinded(&mut RngAdapter(rng), Pkcs1v15Encrypt, ct)
        .map_err(|_| Sw::EXEC_ERROR)?;
    out[..pt.len()].copy_from_slice(&pt);
    let n = pt.len();
    pt.zeroize();
    Ok(n)
}

/// Adapts the crate [`Rng`] to `rand_core` for P-521's randomized signer and the
/// RSA blinding / signing (the curves with a deterministic signer skip it).
/// `pub(crate)` so the applet tests can drive the `rsa` crate's randomized APIs.
pub(crate) struct RngAdapter<'a>(pub(crate) &'a mut dyn Rng);

impl rand_core::RngCore for RngAdapter<'_> {
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
impl rand_core::CryptoRng for RngAdapter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    // The end-to-end (applet) tests in lib.rs cover P-256 + Ed25519; these check
    // the raw r‖s output and public-point round-trip for the heavier curves.
    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn sign_and_verify(curve: Curve, scalar: &[u8], expect_sig_len: usize) {
        let key = PrivKey::from_scalar(curve, scalar).unwrap();
        // A 64-byte (SHA-512-sized) prehash: ≥ half the field for every curve
        // here (`bits2field` rejects anything shorter than that for P-521).
        let digest = [0x42u8; 64];
        let mut sig = [0u8; MAX_EC_SIG];
        let n = key.sign(&digest, &mut SeqRng(1), &mut sig).unwrap();
        assert_eq!(n, expect_sig_len, "raw r‖s width");
        let mut pt = [0u8; MAX_EC_POINT];
        let pn = key.public_point(&mut pt).unwrap();
        let (point, sig) = (&pt[..pn], &sig[..n]);
        match curve {
            Curve::P384 => {
                use p384::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
                let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
                vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                    .unwrap();
            }
            Curve::K256 => {
                use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
                let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
                vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                    .unwrap();
            }
            Curve::P521 => {
                use p521::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
                let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
                vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                    .unwrap();
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn p384_raw_sign_verifies() {
        sign_and_verify(Curve::P384, &[0x11u8; 48], 96);
    }

    #[test]
    fn k256_raw_sign_verifies() {
        sign_and_verify(Curve::K256, &[0x11u8; 32], 64);
    }

    #[test]
    fn p521_raw_sign_verifies() {
        // Top byte 0 keeps the scalar < n (a P-521 scalar is 521 bits).
        let mut scalar = [0x11u8; 66];
        scalar[0] = 0x00;
        sign_and_verify(Curve::P521, &scalar, 132);
    }

    /// The raw RSA fallback must be base-blinded yet still compute `m^d mod n`
    /// exactly, independent of the blinding factor (CT-audit finding #1).
    #[test]
    fn rsa_raw_blinded_equals_unblinded() {
        let key = RsaPrivateKey::new(&mut RngAdapter(&mut SeqRng(7)), 512).unwrap();
        let ks = key.size();
        let data = [0x2au8; 40];
        let mut out = [0u8; MAX_RSA_BYTES];
        let n = rsa_raw(&key, &data, &mut out, &mut SeqRng(99)).unwrap();
        assert_eq!(n, ks);
        let got = BigUint::from_bytes_be(&out[..ks]);
        let want = BigUint::from_bytes_be(&data).modpow(key.d(), key.n());
        assert_eq!(got, want, "blinded raw RSA must equal m^d mod n");
        // The result must not depend on the random blinding factor.
        let mut out2 = [0u8; MAX_RSA_BYTES];
        rsa_raw(&key, &data, &mut out2, &mut SeqRng(424242)).unwrap();
        assert_eq!(out[..ks], out2[..ks], "blinding must cancel");
    }

    /// ECDH Diffie-Hellman symmetry: `ECDH(a, B_pub) == ECDH(b, A_pub)` proves the
    /// new Weierstrass agreements (P-384/P-521/secp256k1) compute the right shared
    /// x-coordinate of the field width. P-256 + X25519 have their own vectors.
    fn ecdh_symmetry(curve: Curve, sa: &[u8], sb: &[u8], zlen: usize) {
        let a = PrivKey::from_scalar(curve, sa).unwrap();
        let b = PrivKey::from_scalar(curve, sb).unwrap();
        let mut pa = [0u8; MAX_EC_POINT];
        let na = a.public_point(&mut pa).unwrap();
        let mut pb = [0u8; MAX_EC_POINT];
        let nb = b.public_point(&mut pb).unwrap();
        let mut z1 = [0u8; 66];
        let n1 = a.ecdh(&pb[..nb], &mut z1).unwrap();
        let mut z2 = [0u8; 66];
        let n2 = b.ecdh(&pa[..na], &mut z2).unwrap();
        assert_eq!(n1, zlen, "shared x-coordinate width");
        assert_eq!(
            &z1[..n1],
            &z2[..n2],
            "DH shared secret must match both ways"
        );
    }

    #[test]
    fn ecdh_weierstrass_dh_symmetry() {
        ecdh_symmetry(Curve::P384, &[0x11; 48], &[0x22; 48], 48);
        ecdh_symmetry(Curve::K256, &[0x11; 32], &[0x22; 32], 32);
        // P-521 scalars need the top byte clear to stay below n.
        let (mut a, mut b) = ([0x11u8; 66], [0x22u8; 66]);
        a[0] = 0;
        b[0] = 0;
        ecdh_symmetry(Curve::P521, &a, &b, 66);
    }

    #[test]
    fn curve_from_attr_matches_oid_only() {
        // ECDSA- and ECDH-tagged P-256 share an OID → same curve.
        assert_eq!(
            curve_from_attr(&[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
            Some(Curve::P256)
        );
        assert_eq!(
            curve_from_attr(&[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
            Some(Curve::P256)
        );
        // RSA / unknown OIDs are not EC curves.
        assert_eq!(curve_from_attr(&[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]), None);
    }
}

#[cfg(test)]
mod rsa_tests {
    use super::*;
    use rsa::RsaPublicKey;

    // A fixed RSA-2048 key (openssl genrsa), primes sans the DER sign byte.
    const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
    const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
    const N_HEX: &str = "ba8654a65ddb75e8cf593ee635345ac0a64d43bd328849683979bf25928cf46489051bf991cdb56a464d83069048c651b049d0181bc08a1e34cb9130a86c67a6283e79100d6c32dce9ddf852ba94cbe1d2b3c89358096cd48a8c90fcb6089819258e44d92d25b0cc4ab2a9224e4489e2eec8abc13a19f520adec2710f8f8ac21b4cebe99a958fe38fe43b50c97375076c2ff5e98980af0c5a719a417ba8f657328ea95f50936d6f459af093bc864b222f89302e9e9972ff491608f7ef93b509c8a65bad0e51bcbf0d2e43d2c9956d762af1d26a01b776471e39a2338babb4f8a30199cf26dd8dbdccf59ef77912b1b700e59c3a7e327ffbb58b6584b827ed449";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn test_key() -> RsaPrivateKey {
        rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(P_HEX), &hex(Q_HEX)).unwrap()
    }

    #[test]
    fn import_recovers_modulus() {
        // from_p_q must reconstruct N = P·Q (the make_rsa_response modulus).
        let key = test_key();
        let mut out = [0u8; MAX_RSA_PUBDO];
        let n = make_rsa_response(&key, &mut out);
        assert_eq!(&out[..3], &[0x7f, 0x49, 0x82]); // outer DO
        assert_eq!(&out[5..7], &[0x81, 0x82]); // modulus tag + 2-byte length
        assert_eq!(u16::from_be_bytes([out[7], out[8]]), 256); // RSA-2048 modulus
        assert_eq!(&out[9..9 + 256], hex(N_HEX).as_slice());
        // Exponent 0x010001 follows the modulus.
        assert_eq!(out[9 + 256], 0x82);
        assert_eq!(out[9 + 256 + 1], 3);
        assert_eq!(&out[9 + 256 + 2..9 + 256 + 5], &[0x01, 0x00, 0x01]);
        assert_eq!(n, 270);
    }

    #[test]
    fn sign_digestinfo_verifies() {
        let key = test_key();
        // A SHA-256 DigestInfo (what gpg sends for an RSA signature).
        let mut di = DI_SHA256.to_vec();
        di.extend_from_slice(&[0x42u8; 32]);
        let mut sig = [0u8; MAX_RSA_BYTES];
        let n = rsa_sign(&key, &di, &mut SeqRng(1), &mut sig).unwrap();
        assert_eq!(n, 256);
        RsaPublicKey::from(&key)
            .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
            .unwrap();
    }

    #[test]
    fn sign_bare_hash_infers_alg() {
        // A bare 32-byte hash is treated as SHA-256 (length inference), so it must
        // verify against the same DigestInfo signature.
        let key = test_key();
        let hash = [0x37u8; 32];
        let mut sig = [0u8; MAX_RSA_BYTES];
        let n = rsa_sign(&key, &hash, &mut SeqRng(2), &mut sig).unwrap();
        let mut di = DI_SHA256.to_vec();
        di.extend_from_slice(&hash);
        RsaPublicKey::from(&key)
            .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
            .unwrap();
    }

    #[test]
    fn decipher_roundtrip() {
        let key = test_key();
        let msg = b"a-32-byte-openpgp-session-key!!!";
        let ct = RsaPublicKey::from(&key)
            .encrypt(&mut RngAdapter(&mut SeqRng(7)), Pkcs1v15Encrypt, msg)
            .unwrap();
        // The DECIPHER command prepends the OpenPGP padding-indicator byte.
        let mut data = vec![0x00u8];
        data.extend_from_slice(&ct);
        let mut out = [0u8; MAX_RSA_BYTES];
        let n = rsa_decipher(&key, &mut SeqRng(8), &data, &mut out).unwrap();
        assert_eq!(&out[..n], msg);
    }

    #[test]
    fn keygen_pool_assembles_in_either_order() {
        // The dual-core search feeds primes through `offer` in whatever order the
        // cores find them — both orders must assemble the same modulus.
        let p = BigUint::from_bytes_be(&hex(P_HEX));
        let q = BigUint::from_bytes_be(&hex(Q_HEX));
        for (first, second) in [(p.clone(), q.clone()), (q, p)] {
            let mut kg = RsaKeygen::new(2048);
            assert!(kg.usable());
            assert_eq!(kg.half_bytes(), 128);
            assert!(matches!(kg.offer(first), RsaStep::More));
            match kg.offer(second) {
                RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
                _ => panic!("two distinct primes must complete the key"),
            }
        }
    }

    #[test]
    fn keygen_pool_le_transport() {
        // The inter-core transport: primes as little-endian bytes, scrubbed on use.
        let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
        p_le.reverse();
        q_le.reverse();
        let mut kg = RsaKeygen::new(2048);
        assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
        assert!(
            p_le.iter().all(|&b| b == 0),
            "transport buffer not scrubbed"
        );
        match kg.offer_le(&mut q_le) {
            RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
            _ => panic!("two distinct primes must complete the key"),
        }
    }

    #[test]
    fn try_candidate_le_finds_exact_half() {
        // Smallest asm-eligible half (32 bytes = RSA-512) so the host search is
        // quick; a find must fill the half exactly, odd and with the top bits set.
        let mut rng = SeqRng(42);
        let mut sieve = IncrementalSieve::new();
        let mut out = [0u8; 32];
        let mut tries = 0;
        let len = loop {
            tries += 1;
            assert!(tries < 200_000, "prime search did not converge");
            if let Some(n) = RsaKeygen::try_candidate_le(&mut sieve, &mut rng, 32, &mut out) {
                break n;
            }
        };
        assert_eq!(len, 32);
        assert_eq!(out[31] & 0xC0, 0xC0);
        assert_eq!(out[0] & 1, 1);
    }

    #[test]
    fn keygen_bpsw_split_matches_library() {
        // try_candidate's accept = strong-MR(asm) + strong-Lucas. Any prime it
        // produces must satisfy the library's own one-call Baillie-PSW — the
        // split changed backends, not the test.
        use num_bigint_dig::prime::probably_prime;
        let mut rng = SeqRng(7);
        let mut sieve = IncrementalSieve::new();
        let (mut found, mut tries) = (0, 0);
        while found < 2 {
            tries += 1;
            assert!(tries < 200_000, "prime search did not converge");
            if let Some(p) = RsaKeygen::try_candidate(&mut sieve, &mut rng, 32) {
                assert!(
                    probably_prime(&p, 0),
                    "split BPSW accepted what the library rejects"
                );
                found += 1;
            }
        }
    }

    #[test]
    fn keygen_pool_rejects_duplicate_prime() {
        let p = BigUint::from_bytes_be(&hex(P_HEX));
        let mut kg = RsaKeygen::new(2048);
        assert!(matches!(kg.offer(p.clone()), RsaStep::More));
        // The same prime again must not assemble a broken p == q key…
        assert!(matches!(kg.offer(p), RsaStep::More));
        // …and the held prime survives: a distinct second one completes the key.
        let q = BigUint::from_bytes_be(&hex(Q_HEX));
        assert!(matches!(kg.offer(q), RsaStep::Done(_)));
    }
}

#[cfg(test)]
mod x25519_tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn x25519_rfc7748_vector() {
        // RFC 7748 §6.1. Alice's scalar arrives as a big-endian OpenPGP MPI (so the
        // little-endian RFC scalar reversed); Bob's public key is the 0x40-prefixed
        // native little-endian u-coordinate. The DECIPHER result is the shared K.
        let alice_le = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let k = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let mut alice_be = alice_le.clone();
        alice_be.reverse();
        let key = PrivKey::from_scalar(Curve::X25519, &alice_be).unwrap();

        let mut point = vec![0x40u8];
        point.extend_from_slice(&bob_pub);
        let mut out = [0u8; 32];
        let n = key.ecdh(&point, &mut out).unwrap();
        assert_eq!(&out[..n], k.as_slice());

        // The peer point is also accepted without the 0x40 native-format prefix.
        let mut out2 = [0u8; 32];
        key.ecdh(&bob_pub, &mut out2).unwrap();
        assert_eq!(out2, out);
    }

    #[test]
    fn x25519_public_point_matches_rfc7748() {
        // Alice's public key is X25519(scalar, basepoint).
        let alice_le = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let mut alice_be = alice_le.clone();
        alice_be.reverse();
        let key = PrivKey::from_scalar(Curve::X25519, &alice_be).unwrap();
        let mut out = [0u8; 32];
        let n = key.public_point(&mut out).unwrap();
        assert_eq!(&out[..n], alice_pub.as_slice());
    }

    #[test]
    fn x25519_rejects_bad_peer_length() {
        let key = PrivKey::from_scalar(Curve::X25519, &[0x11u8; 32]).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(key.ecdh(&[0u8; 31], &mut out), Err(Sw::DATA_INVALID));
        assert_eq!(key.ecdh(&[0u8; 40], &mut out), Err(Sw::DATA_INVALID));
    }
}
