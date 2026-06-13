// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the management applet dispatch (`ManagementApplet::process`): SELECT
//! returns the version string, READ CONFIG builds the capability/serial/version
//! TLV, and WRITE CONFIG parses an attacker-controlled length-prefixed blob it
//! persists to `EF_DEV_CONF` (then READ CONFIG echoes it back). A stream of raw
//! APDUs is replayed against the live applet + flash; none may panic.

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_mgmt::ManagementApplet;
use rsk_sdk::{Apdu, Applet, ResBuf};

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4]);

    // Split the input into length-prefixed APDUs and replay each.
    let mut i = 0;
    while i < data.len() {
        let n = data[i] as usize;
        i += 1;
        let end = (i + n).min(data.len());
        let raw = &data[i..end];
        i = end;
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
});
