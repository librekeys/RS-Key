// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the BER-TLV walker — malformed/overrunning input must end iteration,
//! never panic or read out of bounds.

use libfuzzer_sys::fuzz_target;
use rsk_sdk::tlv::{Tlv, find_tag};

fuzz_target!(|data: &[u8]| {
    for (_tag, _value) in Tlv::new(data) {}
    let _ = find_tag(data, 0x5A);
});
