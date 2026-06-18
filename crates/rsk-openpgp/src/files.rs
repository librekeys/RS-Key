// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The OpenPGP data-object table: resolves each DO tag / FID to its source —
//! a ROM constant, the `rsk-fs` KV store, a computed/composite
//! [`dobj`](crate::dobj) builder, or an internal EF never served by GET DATA.

use crate::consts::*;

/// Historical bytes.
pub const HISTORICAL_BYTES: &[u8] = &[0x00, 0x31, 0x84, 0x73, 0x80, 0x01, 0xC0, 0x05, 0x90, 0x00];

/// Extended capabilities: no secure messaging, GET CHALLENGE (128), key import,
/// PW-status puttable, private DO, changeable algo attrs, AES, KDF-DO.
pub const EXTENDED_CAPABILITIES: &[u8] =
    &[0x7f, 0x00, 0x00, 0x80, 0x08, 0x00, 0x08, 0x00, 0x00, 0x01];

/// Extended length information: max cmd 0x07ff, max rsp 0x0800.
pub const EXLEN_INFO: &[u8] = &[0x02, 0x02, 0x07, 0xff, 0x02, 0x02, 0x08, 0x00];

/// General feature management: button present.
pub const FEATURE_MNGMNT: &[u8] = &[0x81, 0x01, 0x20];

/// Default PW status bytes written to `EF_PW_PRIV` at init: PW1 valid for
/// several PSO:CDS (0x01), max PW lengths 127/127/127, retry counters 3/3/3.
pub const PW_STATUS_DEFAULT: &[u8] = &[
    0x01,
    127,
    127,
    127,
    PW_RETRIES_DEFAULT,
    PW_RETRIES_DEFAULT,
    PW_RETRIES_DEFAULT,
];

/// The computed/composite data objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncDo {
    ChData,     // 0x65 parse_ch_data
    SecTpl,     // 0x7A parse_sec_tpl
    ChCert,     // 0x7F21 — GET/PUT routed to EF_CH_1/2/3 by the dispatcher (occurrence)
    Fp,         // 0xC5 parse_fp
    CaFp,       // 0xC6 parse_cafp
    Ts,         // 0xCD parse_ts
    KeyInfo,    // 0xDE parse_keyinfo
    AlgoInfo,   // 0xC1/0xC2/0xC3/0xFA parse_algoinfo
    AppData,    // 0x6E parse_app_data
    DiscreteDo, // 0x73 parse_discrete_do
    PwStatus,   // 0xC4 parse_pw_status
}

/// Where a DO's data comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoSource {
    Rom(&'static [u8]),
    Flash,
    Func(FuncDo),
    /// The AID-with-serial (`EF_FULL_AID`), assembled by the applet at init.
    FullAid,
    /// Internal EF (private storage): not reachable via GET DATA.
    Internal,
    /// No such file.
    None,
}

/// Resolve a DO tag / FID to its source.
pub fn source(fid: u16) -> DoSource {
    // Private-key and DEK slots are `KeyFid`s (sealed secrets), so they can't be
    // `u16` match patterns; like the other internal EFs they aren't GET-DATA-able.
    if fid == EF_PK_SIG.get()
        || fid == EF_PK_DEC.get()
        || fid == EF_PK_AUT.get()
        || fid == EF_DEK_PW1.get()
        || fid == EF_DEK_RC.get()
        || fid == EF_DEK_PW3.get()
    {
        return DoSource::Internal;
    }
    match fid {
        EF_FULL_AID => DoSource::FullAid,
        EF_HIST_BYTES => DoSource::Rom(HISTORICAL_BYTES),
        EF_EXT_CAP => DoSource::Rom(EXTENDED_CAPABILITIES),
        EF_EXLEN_INFO => DoSource::Rom(EXLEN_INFO),
        EF_GFM => DoSource::Rom(FEATURE_MNGMNT),

        EF_CH_DATA => DoSource::Func(FuncDo::ChData),
        EF_SEC_TPL => DoSource::Func(FuncDo::SecTpl),
        EF_CH_CERT => DoSource::Func(FuncDo::ChCert),
        EF_FP => DoSource::Func(FuncDo::Fp),
        EF_CA_FP => DoSource::Func(FuncDo::CaFp),
        EF_TS_ALL => DoSource::Func(FuncDo::Ts),
        EF_KEY_INFO => DoSource::Func(FuncDo::KeyInfo),
        EF_ALGO_SIG | EF_ALGO_DEC | EF_ALGO_AUT | EF_ALGO_INFO => DoSource::Func(FuncDo::AlgoInfo),
        EF_PW_STATUS => DoSource::Func(FuncDo::PwStatus),
        EF_APP_DATA => DoSource::Func(FuncDo::AppData),
        EF_DISCRETE_DO => DoSource::Func(FuncDo::DiscreteDo),

        // Flash-backed working DOs.
        EF_CH_NAME | EF_LOGIN_DATA | EF_LANG_PREF | EF_SEX | EF_URI_URL | EF_SIG_COUNT
        | EF_FP_SIG | EF_FP_DEC | EF_FP_AUT | EF_FP_CA1 | EF_FP_CA2 | EF_FP_CA3 | EF_TS_SIG
        | EF_TS_DEC | EF_TS_AUT | EF_UIF_SIG | EF_UIF_DEC | EF_UIF_AUT | EF_KDF | EF_RESET_CODE
        | EF_PRIV_DO_1 | EF_PRIV_DO_2 | EF_PRIV_DO_3 | EF_PRIV_DO_4 => DoSource::Flash,

        // Internal EFs (PINs, public-key DOs, base/PWPIV DEK, algo-priv,
        // chaining): not GET-DATA-able. The private-key + PW-DEK slots are
        // handled by the KeyFid guard above.
        EF_PW1 | EF_RC | EF_PW3 | EF_ALGO_PRIV1 | EF_ALGO_PRIV2 | EF_ALGO_PRIV3 | EF_PW_PRIV
        | EF_PW_RETRIES | EF_PB_SIG | EF_PB_DEC | EF_PB_AUT | EF_DEK | EF_DEK_PWPIV | EF_CH_1
        | EF_CH_2 | EF_CH_3 => DoSource::Internal,

        _ => DoSource::None,
    }
}

/// Build the 16-byte full AID with the 4-byte device serial spliced in at
/// offset 10.
pub fn full_aid(serial: &[u8; 4]) -> [u8; 16] {
    let mut aid = [
        0xD2,
        0x76,
        0x00,
        0x01,
        0x24,
        0x01,
        OPGP_VERSION_MAJOR,
        OPGP_VERSION_MINOR,
        0xff,
        0xfe,
        0xff,
        0xff,
        0xff,
        0xff,
        0x00,
        0x00,
    ];
    aid[10..14].copy_from_slice(serial);
    aid
}
