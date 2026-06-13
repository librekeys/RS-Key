// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CTAPHID TX framing ⇄ RX reassembly round-trip: any payload framed
//! by `TxFrames` must reassemble back to the same bytes, command and channel.

use libfuzzer_sys::fuzz_target;
use rsk_usb::ctaphid::{CTAP_MAX_MESSAGE, Outcome, Reassembler, TxFrames};

const CID: u32 = 0x0100_0000;
const CMD: u8 = 0x80 | 0x01; // CTAPHID_PING (TYPE_INIT bit set)

fuzz_target!(|data: &[u8]| {
    if data.len() > CTAP_MAX_MESSAGE {
        return;
    }
    let mut asm = Reassembler::new();
    let mut last = Outcome::None;
    for frame in TxFrames::new(CID, CMD, data) {
        last = asm.feed(&frame);
    }
    match last {
        Outcome::Message(cid, cmd) => {
            assert_eq!(cid, CID);
            assert_eq!(cmd, CMD);
            assert_eq!(asm.message(), data);
        }
        other => panic!("framed message did not reassemble: {other:?}"),
    }
});
