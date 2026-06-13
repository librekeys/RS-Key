// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole PIV applet dispatch (`PivApplet::process`) — the PIV analogue
//! of `openpgp_apdu`/`oath_apdu`/`mgmt_apdu`. The applet is SELECTed (creating
//! the default PINs, management key and F9 attestation cert), authenticated to
//! the default management key and PIN-verified, and seeded with a generated
//! P-256 key in slot 9A so AUTHENTICATE / ATTEST / GET DATA reach real stored
//! blobs. Then a sequence of length-prefixed attacker APDUs is replayed against
//! the live applet + RAM flash, with a SELECT between sequences. None may
//! panic. RSA generate is excluded from the seed (slow prime search); the
//! dispatcher rejects it before keygen anyway.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_piv::{AlwaysConfirm, PivApplet, Rng};
use rsk_sdk::{Apdu, Applet, ResBuf};

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
const DEFAULT_MGM: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

fn run(app: &mut PivApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Vec<u8> {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 4096];
        let mut res = ResBuf::new(&mut buf);
        let _ = app.process(&apdu, fs, &mut res);
        return res.as_slice().to_vec();
    }
    Vec::new()
}

/// Authenticate to the default AES-192 management key (two-step mutual auth).
fn auth_mgm(app: &mut PivApplet, fs: &mut Fs<RamStorage>) {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};
    let wit = run(
        app,
        fs,
        &[0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00],
    );
    if wit.len() < 20 {
        return;
    }
    let cipher = aes::Aes192::new(GenericArray::from_slice(&DEFAULT_MGM));
    let mut w = [0u8; 16];
    w.copy_from_slice(&wit[4..20]);
    let mut blk = GenericArray::clone_from_slice(&w);
    cipher.decrypt_block(&mut blk);
    let mut msg = vec![0x00, 0x87, 0x0A, 0x9B, 0x24, 0x7C, 0x22, 0x80, 0x10];
    msg.extend_from_slice(&blk);
    msg.push(0x81);
    msg.push(0x10);
    msg.extend_from_slice(&[0xA5; 16]);
    let _ = run(app, fs, &msg);
}

fuzz_target!(|data: &[u8]| {
    let rng = RefCell::new(CountRng(0));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &pres);
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();

    // SELECT to initialize the default files.
    {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        let _ = Applet::select(&mut app, false, &mut fs, &mut res);
    }
    auth_mgm(&mut app, &mut fs);
    // VERIFY default PIN.
    let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    verify.extend_from_slice(&DEFAULT_PIN);
    let _ = run(&mut app, &mut fs, &verify);
    // GENERATE P-256 in slot 9A.
    let _ = run(
        &mut app,
        &mut fs,
        &[0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11],
    );

    // Replay attacker APDUs: [len][apdu bytes…]*, with a SELECT between them.
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
        let _ = run(&mut app, &mut fs, &tail[..n]);
        rest = &tail[n..];
    }
});
