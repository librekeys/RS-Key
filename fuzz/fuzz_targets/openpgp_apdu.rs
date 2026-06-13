// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole OpenPGP applet dispatch (`OpenpgpApplet::process`) — the
//! analogue of `fido_cbor` for the CCID side. A freshly-initialised applet is
//! PIN-authenticated (PW3 admin + PW1/PW2) so the parsers behind the PIN gates
//! are reachable, then a sequence of length-prefixed attacker APDUs is replayed
//! against the live applet + flash. This exercises every command parser at once:
//! GET / PUT DATA, VERIFY / CHANGE PIN / RESET RETRY, IMPORT, PSO (incl. the ECDH
//! `parse_ecdh_point` wrapper), INTERNAL AUTHENTICATE and SELECT. None may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_openpgp::consts::{
    INS_VERIFY, PW1_DEFAULT, PW1_MODE81, PW1_MODE82, PW3_DEFAULT, PW3_MODE83,
};
use rsk_openpgp::{OpenpgpApplet, Rng, scan_files};
use rsk_sdk::{Apdu, Applet, ResBuf};

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    }
}

fn run(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 2048];
        let mut res = ResBuf::new(&mut buf);
        let _ = app.process(&apdu, fs, &mut res);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    if scan_files(&dev(), &mut fs, &mut CountRng(0)).is_err() {
        return;
    }
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    // Authenticate so the IMPORT / PSO / INTERNAL-AUT parsers are reachable.
    for (mode, pin) in [
        (PW3_MODE83, PW3_DEFAULT),
        (PW1_MODE81, PW1_DEFAULT),
        (PW1_MODE82, PW1_DEFAULT),
    ] {
        let mut v = vec![0x00, INS_VERIFY, 0x00, mode, pin.len() as u8];
        v.extend_from_slice(pin);
        run(&mut app, &mut fs, &v);
    }

    // Replay a sequence of length-prefixed APDUs (so the fuzzer can chain e.g.
    // PUT DATA then GET DATA, or IMPORT then PSO) against the live applet.
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        let end = (i + len).min(data.len());
        let raw = &data[i..end];
        // Skip on-device GENERATE (INS 0x47, P1 0x80): key generation is not an
        // input parser, and an RSA keygen would dominate the fuzzer's time budget.
        // The generate dispatch is covered by host tests; read-public (P1 0x81) is
        // still fuzzed here.
        let is_generate = raw.len() >= 3 && raw[1] == 0x47 && raw[2] == 0x80;
        if !is_generate {
            run(&mut app, &mut fs, raw);
        }
        i = end;
    }
});
