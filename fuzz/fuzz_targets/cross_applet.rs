// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Stateful cross-applet fuzzing. Every other target drives ONE applet from a
//! fresh state; this one wires the real `rsk_sdk::Dispatcher` to the same applet
//! set the CCID handler registers — OpenPGP, Management, OATH, OTP, PIV — over a
//! single shared flash `Fs` and RNG, then replays an attacker-chosen *sequence*
//! of raw APDUs against it. SELECT-by-AID switches the active applet, command
//! chaining (CLA 0x10) accumulates across commands, and all of it — the
//! dispatcher's selection/chaining state, each applet's PIN/MSE/auth state, and
//! the shared file system — persists across the whole run. The interesting bugs
//! live in the seams: state from one applet leaking into another, a SELECT
//! arriving mid-chain, one applet's FID colliding with another's. Nothing may
//! panic and every response must fit its buffer.
//!
//! Two deliberate scope cuts vs the firmware dispatcher:
//!   * The `VendorApplet` (index 0 on device) is firmware-local, so it is absent
//!     here — its AID simply never selects.
//!   * INS 0x47 (GENERATE) is skipped: on device the slow RSA prime search is
//!     fast-pathed *outside* the dispatcher, and running it inline would hang the
//!     fuzzer. EC generate is covered by the dedicated `openpgp_ec_key` target.
//!   * The `RescueApplet` needs a `Platform`; left out of this set.

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_mgmt::ManagementApplet;
use rsk_oath::OathApplet;
use rsk_openpgp::OpenpgpApplet;
use rsk_otp::OtpApplet;
use rsk_piv::PivApplet;
use rsk_sdk::{Apdu, Applet, Dispatcher, ResBuf};

use core::cell::RefCell;

const INS_GENERATE: u8 = 0x47;

/// Deterministic host RNG; one instance feeds OpenPGP, OATH and PIV (which
/// re-exports OpenPGP's `Rng`), mirroring the single shared TRNG on device.
struct SeqRng(u64);
impl SeqRng {
    fn next(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}
impl rsk_openpgp::Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.next(buf)
    }
}
impl rsk_oath::Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.next(buf)
    }
}

fuzz_target!(|data: &[u8]| {
    const SERIAL_ID: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();

    let rng = RefCell::new(SeqRng(1));
    // PIV and OpenPGP share the user-presence trait (and the button on device);
    // OATH and OTP each have their own.
    let pgp_pres = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let oath_pres = RefCell::new(rsk_oath::AlwaysConfirm);
    let otp_pres = RefCell::new(rsk_otp::AlwaysConfirm);

    let mut openpgp = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &pgp_pres);
    let mut management = ManagementApplet::new(SERIAL_ID);
    let mut oath = OathApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &oath_pres);
    let mut otp = OtpApplet::new(SERIAL_ID, &otp_pres);
    let mut piv = PivApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &pgp_pres);

    let mut disp = Dispatcher::new();
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 5] =
        [&mut openpgp, &mut management, &mut oath, &mut otp, &mut piv];

    // Split the input into length-prefixed APDUs and replay each against the
    // shared dispatcher + flash; selection and chaining state carry across.
    let mut resp = [0u8; 2048];
    let mut i = 0;
    while i < data.len() {
        let n = data[i] as usize;
        i += 1;
        let end = (i + n).min(data.len());
        let raw = &data[i..end];
        i = end;

        // Skip GENERATE: the slow RSA path is off-dispatcher on device.
        if let Ok(p) = Apdu::parse(raw) {
            if p.ins == INS_GENERATE {
                continue;
            }
        }

        let mut res = ResBuf::new(&mut resp);
        let _ = disp.process(raw, &mut applets, &mut fs, &mut res);
        assert!(res.len() <= 2048);
    }
});
