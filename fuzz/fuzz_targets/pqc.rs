// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz the PQC deserialization paths: the ML-DSA-44 public-key/signature
//! decode behind `mldsa44_verify`, the ML-KEM-768 encapsulation-key decode
//! behind `mlkem768_encapsulate`, and decapsulation of arbitrary ciphertexts.
//! All inputs are attacker-shaped bytes; nothing here may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsk_crypto::mldsa::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN};
use rsk_crypto::mlkem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM768_SEED_LEN};
use rsk_crypto::{MlKem768Pair, mldsa44_verify, mlkem768_encapsulate};

fuzz_target!(|data: &[u8]| {
    let mut pk = [0u8; MLDSA44_PK_LEN];
    let mut sig = [0u8; MLDSA44_SIG_LEN];
    let mut ek = [0u8; MLKEM768_EK_LEN];
    let mut ct = [0u8; MLKEM768_CT_LEN];
    for (dst, chunk) in [
        (&mut pk[..], 0),
        (&mut sig[..], 1),
        (&mut ek[..], 2),
        (&mut ct[..], 3),
    ] {
        // Spread the input across the four buffers, offset per buffer so short
        // inputs still differentiate them.
        let (dst, salt) = (dst, chunk);
        for (i, b) in dst.iter_mut().enumerate() {
            *b = data
                .get((i + salt) % data.len().max(1))
                .copied()
                .unwrap_or(salt as u8);
        }
    }

    let _ = mldsa44_verify(&pk, data, &sig);
    let _ = mlkem768_encapsulate(&ek, &[0u8; 32]);

    let mut seed = [0u8; MLKEM768_SEED_LEN];
    let n = data.len().min(MLKEM768_SEED_LEN);
    seed[..n].copy_from_slice(&data[..n]);
    let pair = MlKem768Pair::from_seed(&seed);
    let _ = pair.decapsulate(&ct);
});
