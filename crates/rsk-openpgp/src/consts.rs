// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OpenPGP applet constants: AID/ATR, instruction bytes, EF/DO FIDs, PIN modes,
//! and DEK sizing.

use rsk_fs::KeyFid;

/// OpenPGP application identifier.
pub const OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// OpenPGP card spec version 3.4.
pub const OPGP_VERSION_MAJOR: u8 = 0x03;
pub const OPGP_VERSION_MINOR: u8 = 0x04;

/// Firmware version reported by the vendor VERSION command (INS 0xF1); the
/// value pico-openpgp host tools expect.
pub const PIPGP_VERSION_MAJOR: u8 = 0x04;
pub const PIPGP_VERSION_MINOR: u8 = 0x06;

// Algorithm IDs (first byte of an algorithm-attributes DO).
pub const ALGO_RSA: u8 = 0x01;
pub const ALGO_ECDH: u8 = 0x12;
pub const ALGO_ECDSA: u8 = 0x13;
pub const ALGO_EDDSA: u8 = 0x16;
pub const ALGO_AES: u8 = 0x70;
pub const ALGO_AES_128: u8 = 0x71;
pub const ALGO_AES_192: u8 = 0x72;
pub const ALGO_AES_256: u8 = 0x74;

/// ATR for the OpenPGP card.
pub const ATR_OPENPGP: &[u8] = &[
    0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03, 0x00, 0x31, 0xf5, 0x73, 0xc0, 0x01,
    0x60, 0x00, 0x90, 0x00, 0x1c,
];

// ---------------- APDU instruction bytes ----------------
pub const INS_SELECT_DATA: u8 = 0xA5;
pub const INS_GET_DATA: u8 = 0xCA;
pub const INS_GET_NEXT_DATA: u8 = 0xCC;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_CHANGE_PIN: u8 = 0x24;
pub const INS_RESET_RETRY: u8 = 0x2C;
pub const INS_KEYPAIR_GEN: u8 = 0x47;
pub const INS_PSO: u8 = 0x2A;
pub const INS_INTERNAL_AUT: u8 = 0x88;
pub const INS_SELECT: u8 = 0xA4;
pub const INS_CHALLENGE: u8 = 0x84;
pub const INS_TERMINATE_DF: u8 = 0xE6;
pub const INS_ACTIVATE_FILE: u8 = 0x44;
pub const INS_PUT_DATA: u8 = 0xDA;
pub const INS_PUT_DATA_ODD: u8 = 0xDB; // IMPORT (extended header list)
pub const INS_MSE: u8 = 0x22;
pub const INS_VERSION: u8 = 0xF1;

// ---------------- Internal EF FIDs (flash-backed) ----------------
pub const EF_PW1: u16 = 0x1081;
pub const EF_RC: u16 = 0x1082;
pub const EF_PW3: u16 = 0x1083;
pub const EF_ALGO_PRIV1: u16 = 0x10c1;
pub const EF_ALGO_PRIV2: u16 = 0x10c2;
pub const EF_ALGO_PRIV3: u16 = 0x10c3;
pub const EF_PW_PRIV: u16 = 0x10c4;
pub const EF_PW_RETRIES: u16 = 0x10c5;
pub const EF_PK_SIG: KeyFid = KeyFid::new(0x10d1); // private SIG key, DEK-sealed
pub const EF_PK_DEC: KeyFid = KeyFid::new(0x10d2); // private DEC key, DEK-sealed
pub const EF_PK_AUT: KeyFid = KeyFid::new(0x10d3); // private AUT key, DEK-sealed
pub const EF_PB_SIG: u16 = 0x10d4; // public-key DO = EF_PK_SIG + 3 (not secret)
pub const EF_PB_DEC: u16 = 0x10d5;
pub const EF_PB_AUT: u16 = 0x10d6;
pub const EF_DEK: u16 = 0x1099;
pub const EF_DEK_PW1: KeyFid = KeyFid::new(0x109a); // DEK wrapped under PW1
pub const EF_DEK_RC: KeyFid = KeyFid::new(0x109b); // DEK wrapped under reset code
pub const EF_DEK_PW3: KeyFid = KeyFid::new(0x109c); // DEK wrapped under PW3
pub const EF_DEK_PWPIV: u16 = 0x109d;
pub const EF_CH_1: u16 = 0x1f21;
pub const EF_CH_2: u16 = 0x1f22;
pub const EF_CH_3: u16 = 0x1f23;

// ---------------- Data-object FIDs / tags (tag == FID) ----------------
// `//C` = computed/composite DO, `//S` = stored DO.
pub const EF_EXT_HEADER: u16 = 0x004d; // C — extended header list (IMPORT)
pub const EF_FULL_AID: u16 = 0x004f; // S
pub const EF_CH_NAME: u16 = 0x005b; // S
pub const EF_LOGIN_DATA: u16 = 0x005e; // S
pub const EF_CH_DATA: u16 = 0x0065; // C — cardholder related data
pub const EF_APP_DATA: u16 = 0x006e; // C — application related data
pub const EF_DISCRETE_DO: u16 = 0x0073; // C
pub const EF_SEC_TPL: u16 = 0x007a; // C — security support template
pub const EF_SIG_COUNT: u16 = 0x0093; // S — signature counter (3 bytes)
pub const EF_EXT_CAP: u16 = 0x00c0; // S — extended capabilities
pub const EF_ALGO_SIG: u16 = 0x00c1; // S — algorithm attributes (SIG)
pub const EF_ALGO_DEC: u16 = 0x00c2; // S
pub const EF_ALGO_AUT: u16 = 0x00c3; // S
pub const EF_PW_STATUS: u16 = 0x00c4; // S — PW status bytes (7)
pub const EF_FP: u16 = 0x00c5; // S — fingerprints (3×20)
pub const EF_CA_FP: u16 = 0x00c6; // S — CA fingerprints (3×20)
pub const EF_FP_SIG: u16 = 0x00c7; // S
pub const EF_FP_DEC: u16 = 0x00c8; // S
pub const EF_FP_AUT: u16 = 0x00c9; // S
pub const EF_FP_CA1: u16 = 0x00ca; // S
pub const EF_FP_CA2: u16 = 0x00cb; // S
pub const EF_FP_CA3: u16 = 0x00cc; // S
pub const EF_TS_ALL: u16 = 0x00cd; // S — generation timestamps (3×4)
pub const EF_TS_SIG: u16 = 0x00ce; // S
pub const EF_TS_DEC: u16 = 0x00cf; // S
pub const EF_TS_AUT: u16 = 0x00d0; // S
pub const EF_RESET_CODE: u16 = 0x00d3; // S — PUT redirects to EF_RC
pub const EF_AES_KEY: KeyFid = KeyFid::new(0x00d5); // S — symmetric key for DEC slot, DEK-sealed
pub const EF_UIF_SIG: u16 = 0x00d6; // S — user-interaction flag (touch)
pub const EF_UIF_DEC: u16 = 0x00d7; // S
pub const EF_UIF_AUT: u16 = 0x00d8; // S
pub const EF_KEY_INFO: u16 = 0x00de; // S
pub const EF_KDF: u16 = 0x00f9; // C — KDF parameters
pub const EF_ALGO_INFO: u16 = 0x00fa; // C — algorithm info
pub const EF_LANG_PREF: u16 = 0x5f2d; // S
pub const EF_SEX: u16 = 0x5f35; // S
pub const EF_URI_URL: u16 = 0x5f50; // S
pub const EF_HIST_BYTES: u16 = 0x5f52; // S — historical bytes
pub const EF_CH_CERT: u16 = 0x7f21; // C
pub const EF_EXLEN_INFO: u16 = 0x7f66; // C — extended length info
pub const EF_GFM: u16 = 0x7f74; // C
pub const EF_PRIV_DO_1: u16 = 0x0101;
pub const EF_PRIV_DO_2: u16 = 0x0102;
pub const EF_PRIV_DO_3: u16 = 0x0103;
pub const EF_PRIV_DO_4: u16 = 0x0104;

// ---------------- PIN modes (VERIFY/CHANGE P2) ----------------
pub const PW1_MODE81: u8 = 0x81; // user PIN, signing
pub const PW1_MODE82: u8 = 0x82; // user PIN, other ops (PW2)
pub const PW3_MODE83: u8 = 0x83; // admin PIN

// ---------------- Sizes / fixed parameters ----------------
pub const IV_SIZE: usize = 16;
/// The sealed DEK plaintext is a 16-byte IV followed by the 32-byte key,
/// so it is 48 bytes (NOT 32).
pub const DEK_SIZE: usize = IV_SIZE + 32;
/// Sealed-blob size: 12-byte GCM nonce + ciphertext + 16-byte tag.
pub const fn pin_kdf_size(plaintext: usize) -> usize {
    12 + plaintext + 16
}
/// The wrapped DEK blob (76 bytes).
pub const DEK_AAD_SIZE: usize = pin_kdf_size(DEK_SIZE);
/// Format byte + wrapped DEK blob (77 bytes).
pub const DEK_FILE_SIZE: usize = 1 + DEK_AAD_SIZE;
/// Default retry counters (PW1, RC, PW3) initialised by the applet.
pub const PW_RETRIES_DEFAULT: u8 = 3;
/// Default user PIN `123456`, admin PIN `12345678` (the OpenPGP defaults).
pub const PW1_DEFAULT: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
pub const PW3_DEFAULT: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
