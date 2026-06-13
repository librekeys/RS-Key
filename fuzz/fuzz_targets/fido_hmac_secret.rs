// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the hmac-secret extension parser + evaluator: an arbitrary extension map
//! (COSE keyAgreement + salts) must parse without panicking, and evaluating it
//! against a fixed ephemeral key / credential must stay in bounds and never panic
//! (most inputs fail the ECDH, MAC or salt-length checks and return an error).

use libfuzzer_sys::fuzz_target;
use rsk_fido::Rng;
use rsk_fido::hmacsecret;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = hmacsecret::parse_bytes(data) {
        let mut rng = SeqRng(1);
        let ephemeral = [0x11u8; 32];
        let seed = [0x42u8; 32];
        let cred_id = [0x55u8; 80];
        let mut out = [0u8; 80];
        let _ = hmacsecret::eval(&req, &ephemeral, &seed, &cred_id, false, &mut rng, &mut out);
    }
});
