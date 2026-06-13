// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole Yubico-OTP applet dispatch (`OtpApplet::process`). A slot is
//! seeded with an HMAC challenge-response config through the real configure
//! path (so calculate / update / swap reach stored data), then a sequence of
//! length-prefixed attacker APDUs is replayed against the live applet + RAM
//! flash. None may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_otp::{AlwaysConfirm, OtpApplet};
use rsk_sdk::{Apdu, Applet, ResBuf};

fn run(app: &mut OtpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 1024];
        let mut res = ResBuf::new(&mut buf);
        let _ = app.process(&apdu, fs, &mut res);
    }
}

/// CRC16 X.25 (mirrors the applet's) for building one valid seed config.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OtpApplet::new([1, 2, 3, 4, 5, 6, 7, 8], &presence);

    // Seed slot 1: HMAC chal-resp config (tkt 0x40, cfg 0x22) + valid CRC.
    let mut cfg = [0u8; 52];
    cfg[22..38].copy_from_slice(&[0xAB; 16]); // AES/HMAC key field
    cfg[46] = 0x40; // tkt: CHAL_RESP
    cfg[47] = 0x26; // cfg: CHAL_HMAC | HMAC_LT64
    let crc = !crc16(&cfg[..50]);
    cfg[50..].copy_from_slice(&crc.to_le_bytes());
    let mut put = vec![0x00, 0x01, 0x01, 0x00, 58];
    put.extend_from_slice(&cfg);
    put.extend_from_slice(&[0; 6]); // access code
    run(&mut app, &mut fs, &put);

    // Replay attacker APDUs: [len][apdu bytes…]*, 0 = re-SELECT.
    let mut rest = data;
    while let Some((&n, tail)) = rest.split_first() {
        if n == 0 {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = Applet::select(&mut app, false, &mut fs, &mut res);
            rest = tail;
            continue;
        }
        let n = (n as usize).min(tail.len());
        run(&mut app, &mut fs, &tail[..n]);
        rest = &tail[n..];
    }
});
