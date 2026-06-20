// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ML-KEM-768 (FIPS 203) key encapsulation over `ml-kem` — scaffolding for a
//! future PQC PIN/UV-auth protocol; nothing in the applet layer calls it yet.
//! As in [`crate::mldsa`], all randomness is passed in (the 64-byte keygen seed
//! `d‖z`, the 32-byte encapsulation randomness `m`) for deterministic tests.

use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};

use crate::{Error, Result};

/// Keygen seed length (`d ‖ z`, 32 + 32).
pub const MLKEM768_SEED_LEN: usize = 64;
/// Serialized encapsulation (public) key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// Ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Shared-secret length.
pub const MLKEM768_SS_LEN: usize = 32;

/// An ML-KEM-768 decapsulation keypair expanded from a 64-byte seed.
///
/// The decapsulation key zeroizes on drop (`ml-kem`'s `zeroize` feature).
pub struct MlKem768Pair {
    dk: DecapsulationKey<MlKem768>,
}

impl MlKem768Pair {
    /// Deterministically expand the keypair from `d ‖ z` — same seed, same keys.
    pub fn from_seed(seed: &[u8; MLKEM768_SEED_LEN]) -> Self {
        Self {
            dk: DecapsulationKey::from_seed(ml_kem::Seed::from(*seed)),
        }
    }

    /// The serialized encapsulation key (what the peer encapsulates to).
    pub fn encapsulation_key(&self) -> [u8; MLKEM768_EK_LEN] {
        self.dk.encapsulation_key().to_bytes().into()
    }

    /// Recover the shared secret from a peer's ciphertext. ML-KEM never fails
    /// on a well-formed-length ciphertext — a corrupted one yields the implicit
    ///-rejection secret, which simply won't match the peer's.
    pub fn decapsulate(&self, ct: &[u8; MLKEM768_CT_LEN]) -> [u8; MLKEM768_SS_LEN] {
        self.dk
            .decapsulate_slice(ct)
            .expect("fixed-length ciphertext")
            .into()
    }
}

/// Encapsulate to a peer's serialized key: returns `(ciphertext, shared_secret)`.
/// `m` is the FIPS 203 encapsulation randomness — fresh RNG bytes in firmware, a
/// fixed value in tests. Fails on a malformed (non-reduced) encapsulation key.
pub fn mlkem768_encapsulate(
    ek: &[u8; MLKEM768_EK_LEN],
    m: &[u8; 32],
) -> Result<([u8; MLKEM768_CT_LEN], [u8; MLKEM768_SS_LEN])> {
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::from(*ek);
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| Error::Pqc)?;
    let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m));
    Ok((ct.into(), ss.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; MLKEM768_SEED_LEN] = [0x42; MLKEM768_SEED_LEN];

    #[test]
    fn keygen_is_deterministic_and_seed_sensitive() {
        let a = MlKem768Pair::from_seed(&SEED);
        let b = MlKem768Pair::from_seed(&SEED);
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());

        let mut other = SEED;
        other[0] ^= 1;
        let c = MlKem768Pair::from_seed(&other);
        assert_ne!(a.encapsulation_key(), c.encapsulation_key());
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        let pair = MlKem768Pair::from_seed(&SEED);
        let (ct, ss_peer) = mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
        let ss_own = pair.decapsulate(&ct);
        assert_eq!(ss_peer, ss_own);
    }

    #[test]
    fn fixed_m_reproducible() {
        let pair = MlKem768Pair::from_seed(&SEED);
        let ek = pair.encapsulation_key();
        let (ct1, ss1) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
        let (ct2, ss2) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn corrupted_ciphertext_implicitly_rejects() {
        let pair = MlKem768Pair::from_seed(&SEED);
        let (mut ct, ss_peer) =
            mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
        ct[0] ^= 1;
        // No panic, no error — just a shared secret that matches nothing.
        assert_ne!(pair.decapsulate(&ct), ss_peer);
    }

    #[test]
    fn malformed_ek_rejected() {
        // An all-0xFF key has non-reduced coefficients → InvalidKey.
        assert!(mlkem768_encapsulate(&[0xFF; MLKEM768_EK_LEN], &[0u8; 32]).is_err());
    }

    /// Emit a deterministic KAT (fixed `d‖z` seed + fixed `m`) so the host
    /// toolchain's ML-KEM-768 (OpenSSL, via `cryptography`) can be cross-checked
    /// against this RustCrypto implementation off-device: same seed must give the
    /// same `ek`, and the host must decapsulate this `ct` back to this `ss`. Run:
    /// `cargo test -p rsk-crypto --target <host> --ignored mlkem_interop_kat -- --nocapture`
    #[test]
    #[ignore = "prints an interop KAT for the host ML-KEM cross-check"]
    fn mlkem_interop_kat() {
        fn hex(b: &[u8]) -> std::string::String {
            let mut s = std::string::String::new();
            for x in b {
                s.push_str(&std::format!("{x:02x}"));
            }
            s
        }
        let seed = [0x5Au8; MLKEM768_SEED_LEN];
        let m = [0x3Cu8; 32];
        let pair = MlKem768Pair::from_seed(&seed);
        let ek = pair.encapsulation_key();
        let (ct, ss) = mlkem768_encapsulate(&ek, &m).unwrap();
        std::println!("SEED {}", hex(&seed));
        std::println!("EK {}", hex(&ek));
        std::println!("CT {}", hex(&ct));
        std::println!("SS {}", hex(&ss));
    }
}
