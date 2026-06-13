// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CTAPHID frame reassembler with arbitrary 64-byte reports: the host
//! drives this state machine with untrusted input, so it must never panic and
//! must keep its buffer invariants.

use libfuzzer_sys::fuzz_target;
use rsk_usb::ctaphid::{CTAP_MAX_MESSAGE, HID_RPT_SIZE, Outcome, Reassembler};

fuzz_target!(|data: &[u8]| {
    let mut asm = Reassembler::new();
    for chunk in data.chunks(HID_RPT_SIZE) {
        let mut frame = [0u8; HID_RPT_SIZE];
        frame[..chunk.len()].copy_from_slice(chunk);
        if let Outcome::Message(_cid, _cmd) = asm.feed(&frame) {
            assert!(asm.message().len() <= CTAP_MAX_MESSAGE);
        }
    }
});
