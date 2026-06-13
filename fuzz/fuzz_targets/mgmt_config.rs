// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Structured WRITE→READ stress of the management config store. The generic
//! `mgmt_apdu` target replays arbitrary APDU bytes, so it only reaches the
//! interesting state by chance: WRITE CONFIG's `data[0] == nc - 1` framing
//! constraint plus a >64-byte blob plus a following READ is a low-probability
//! combination from random input. This target *constructs* a valid WRITE CONFIG
//! for every blob the fuzzer supplies (any length, including past the 64-byte
//! read buffer) and always reads it back, so the blob-length dimension — the one
//! that hid the EF_DEV_CONF over-length panic — is explored directly against the
//! persisted flash. Nothing may panic.

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_mgmt::ManagementApplet;
use rsk_sdk::{Apdu, Applet, ResBuf};

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;

fn run(app: &mut ManagementApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        let _ = app.process(&apdu, fs, &mut res);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4]);

    // Consume the input as a sequence of `(len, blob)` writes; after each one,
    // read the config back. State persists in `fs` across the whole sequence.
    let mut i = 0;
    while i < data.len() {
        let inner = data[i] as usize; // 0..=255 — short Lc fits, may exceed 64
        i += 1;
        let end = (i + inner).min(data.len());
        let blob = &data[i..end];
        i = end;

        // A valid WRITE CONFIG: leading length byte = inner length, then blob.
        let mut cmd = std::vec![
            0x00,
            INS_WRITE_CONFIG,
            0,
            0,
            (blob.len() + 1) as u8,
            blob.len() as u8,
        ];
        cmd.extend_from_slice(blob);
        run(&mut app, &mut fs, &cmd);

        // Read it back over every interface that serves the DeviceInfo TLV.
        run(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let _ = app.read_config(&mut fs, &mut res);
    }
});
