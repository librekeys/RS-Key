// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Data-object builders. Each `parse_*` appends BER-TLV to the [`DoWriter`]
//! output cursor, reading sub-objects from flash or the ROM table.

use rsk_fs::{Fs, Storage};

use crate::consts::*;
use crate::files::{DoSource, FuncDo, source};

// Algorithm-attribute templates, each prefixed with its TLV length byte —
// `parse_algo` copies `algo[0]+1` bytes after the tag.
const ATTR_RSA1K: &[u8] = &[6, ALGO_RSA, 0x04, 0x00, 0x00, 0x20, 0x00];
const ATTR_RSA2K: &[u8] = &[6, ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00];
const ATTR_RSA3K: &[u8] = &[6, ALGO_RSA, 0x0C, 0x00, 0x00, 0x20, 0x00];
const ATTR_RSA4K: &[u8] = &[6, ALGO_RSA, 0x10, 0x00, 0x00, 0x20, 0x00];
pub(crate) const ATTR_P256K1: &[u8] = &[6, ALGO_ECDSA, 0x2b, 0x81, 0x04, 0x00, 0x0a];
pub(crate) const ATTR_P256R1: &[u8] = &[
    9, ALGO_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];
pub(crate) const ATTR_P384R1: &[u8] = &[6, ALGO_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x22];
pub(crate) const ATTR_P521R1: &[u8] = &[6, ALGO_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x23];
// brainpoolP256r1/384r1/512r1 are NOT advertised (0xfa) nor matched (curve_from_attr):
// RustCrypto's bp256/bp384 expose only WIP arithmetic and there is no bp512 crate,
// so shipping brainpool would mean unaudited curve math.
pub(crate) const ATTR_CV25519: &[u8] = &[
    11, ALGO_ECDH, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
];
const ATTR_X448: &[u8] = &[4, ALGO_ECDH, 0x2b, 0x65, 0x6f];
pub(crate) const ATTR_ED25519: &[u8] = &[
    10, ALGO_EDDSA, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
];
const ATTR_ED448: &[u8] = &[4, ALGO_EDDSA, 0x2b, 0x65, 0x71];

/// Builds DO responses into a caller buffer, reading sub-DOs from `fs`.
pub struct DoWriter<'a, S: Storage> {
    out: &'a mut [u8],
    pos: usize,
    fs: &'a mut Fs<S>,
    full_aid: &'a [u8; 16],
}

impl<'a, S: Storage> DoWriter<'a, S> {
    pub fn new(out: &'a mut [u8], fs: &'a mut Fs<S>, full_aid: &'a [u8; 16]) -> Self {
        Self {
            out,
            pos: 0,
            fs,
            full_aid,
        }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.out[..self.pos]
    }

    fn push(&mut self, b: u8) {
        if self.pos < self.out.len() {
            self.out[self.pos] = b;
            self.pos += 1;
        }
    }

    fn extend(&mut self, s: &[u8]) {
        let n = s.len().min(self.out.len() - self.pos);
        self.out[self.pos..self.pos + n].copy_from_slice(&s[..n]);
        self.pos += n;
    }

    /// BER-TLV length encoding: 1 byte (<128), `81 LL` (<256), or `82 HH LL`.
    fn fmt_len(&mut self, len: usize) {
        if len < 0x80 {
            self.push(len as u8);
        } else if len < 0x100 {
            self.push(0x81);
            self.push(len as u8);
        } else {
            self.push(0x82);
            self.push((len >> 8) as u8);
            self.push((len & 0xff) as u8);
        }
    }

    fn read_flash(&mut self, fid: u16) {
        if let Some(n) = self.fs.read(fid, &mut self.out[self.pos..]) {
            self.pos += n;
        }
    }

    /// Top-level builder for a GET DATA tag: `[1, fid]` with `mode == 1`.
    pub fn build(&mut self, fid: u16) -> usize {
        self.parse_do(&[1, fid], 1)
    }

    /// Walk a fid list, appending each sub-DO. For a multi-element list (a
    /// constructed DO) each child is tag + length prefixed.
    fn parse_do(&mut self, fids: &[u16], mode: i32) -> usize {
        let mut len = 0usize;
        let count = fids[0] as usize;
        for i in 0..count {
            let fid = fids[i + 1];
            match source(fid) {
                DoSource::Func(f) => len += self.parse_func(f, fid, mode),
                DoSource::None | DoSource::Internal => {}
                src => {
                    let data_len = match src {
                        DoSource::Rom(c) => c.len(),
                        DoSource::FullAid => self.full_aid.len(),
                        DoSource::Flash => self.fs.size(fid).unwrap_or(0),
                        _ => 0,
                    };
                    if mode == 1 {
                        if count > 1 && self.pos > 0 {
                            if fid < 0x0100 {
                                self.push((fid & 0xff) as u8);
                            } else {
                                self.push((fid >> 8) as u8);
                                self.push((fid & 0xff) as u8);
                            }
                            self.fmt_len(data_len);
                        }
                        match src {
                            DoSource::Rom(c) => self.extend(c),
                            DoSource::FullAid => {
                                let a = *self.full_aid;
                                self.extend(&a);
                            }
                            DoSource::Flash => self.read_flash(fid),
                            _ => {}
                        }
                    }
                    len += data_len;
                }
            }
        }
        len
    }

    fn parse_func(&mut self, f: FuncDo, fid: u16, mode: i32) -> usize {
        match f {
            FuncDo::AppData => self.parse_app_data(mode),
            FuncDo::ChData => self.parse_ch_data(mode),
            FuncDo::DiscreteDo => self.parse_discrete_do(mode),
            FuncDo::SecTpl => self.parse_sec_tpl(),
            FuncDo::Fp => self.parse_fp(),
            FuncDo::CaFp => self.parse_cafp(),
            FuncDo::Ts => self.parse_ts(),
            FuncDo::KeyInfo => self.parse_keyinfo(),
            FuncDo::PwStatus => self.parse_pw_status(),
            FuncDo::AlgoInfo => self.parse_algoinfo(fid),
            FuncDo::ChCert => 0,
        }
    }

    /// A constructed DO: outer tag (1 byte) + `82 HH LL` + nested, length
    /// back-patched.
    fn constructed(&mut self, tag: u8, fids: &[u16], mode: i32) -> usize {
        self.push(tag);
        self.push(0x82);
        let lp = self.pos;
        self.pos += 2;
        self.parse_do(fids, mode);
        let lpdif = self.pos - lp - 2;
        self.out[lp] = (lpdif >> 8) as u8;
        self.out[lp + 1] = (lpdif & 0xff) as u8;
        lpdif + 4
    }

    fn parse_app_data(&mut self, mode: i32) -> usize {
        let fids = [
            6,
            EF_FULL_AID,
            EF_HIST_BYTES,
            EF_EXLEN_INFO,
            EF_GFM,
            EF_DISCRETE_DO,
            EF_KEY_INFO,
        ];
        self.constructed((EF_APP_DATA & 0xff) as u8, &fids, mode)
    }

    fn parse_ch_data(&mut self, mode: i32) -> usize {
        let fids = [3, EF_CH_NAME, EF_LANG_PREF, EF_SEX];
        self.constructed((EF_CH_DATA & 0xff) as u8, &fids, mode)
    }

    fn parse_discrete_do(&mut self, mode: i32) -> usize {
        let fids = [
            11,
            EF_EXT_CAP,
            EF_ALGO_SIG,
            EF_ALGO_DEC,
            EF_ALGO_AUT,
            EF_PW_STATUS,
            EF_FP,
            EF_CA_FP,
            EF_TS_ALL,
            EF_UIF_SIG,
            EF_UIF_DEC,
            EF_UIF_AUT,
        ];
        self.constructed((EF_DISCRETE_DO & 0xff) as u8, &fids, mode)
    }

    fn parse_sec_tpl(&mut self) -> usize {
        self.push((EF_SEC_TPL & 0xff) as u8);
        self.push(5);
        if self.fs.has_data(EF_SIG_COUNT) {
            self.push((EF_SIG_COUNT & 0xff) as u8);
            self.push(3);
            self.read_flash(EF_SIG_COUNT);
        }
        5 + 2
    }

    /// `num` consecutive fids, each `size` bytes; absent ones zero-filled.
    fn parse_trium(&mut self, fid: u16, num: usize, size: usize) -> usize {
        for i in 0..num {
            let f = fid + i as u16;
            if self.fs.has_data(f) {
                self.read_flash(f);
            } else {
                for _ in 0..size {
                    self.push(0);
                }
            }
        }
        num * size
    }

    fn parse_fp(&mut self) -> usize {
        self.push((EF_FP & 0xff) as u8);
        self.push(60);
        self.parse_trium(EF_FP_SIG, 3, 20) + 2
    }

    fn parse_cafp(&mut self) -> usize {
        self.push((EF_CA_FP & 0xff) as u8);
        self.push(60);
        self.parse_trium(EF_FP_CA1, 3, 20) + 2
    }

    fn parse_ts(&mut self) -> usize {
        self.push((EF_TS_ALL & 0xff) as u8);
        self.push(12);
        self.parse_trium(EF_TS_SIG, 3, 4) + 2
    }

    fn parse_keyinfo(&mut self) -> usize {
        let init = self.pos;
        if self.pos > 0 {
            self.push((EF_KEY_INFO & 0xff) as u8);
            self.push(6);
        }
        for (slot, fid) in [(0u8, EF_PK_SIG), (1, EF_PK_DEC), (2, EF_PK_AUT)] {
            self.push(slot);
            let present = self.fs.has_key(fid);
            self.push(if present { 0x01 } else { 0x00 });
        }
        self.pos - init
    }

    fn parse_pw_status(&mut self) -> usize {
        let init = self.pos;
        if self.pos > 0 {
            self.push((EF_PW_STATUS & 0xff) as u8);
            self.push(7);
        }
        if self.fs.has_data(EF_PW_PRIV) {
            self.read_flash(EF_PW_PRIV);
        }
        self.pos - init
    }

    /// Append `tag | length-prefixed-template`.
    fn parse_algo(&mut self, algo: &[u8], tag: u16) -> usize {
        self.push((tag & 0xff) as u8);
        let n = algo[0] as usize + 1;
        self.extend(&algo[..n]);
        algo[0] as usize + 2
    }

    fn parse_algoinfo(&mut self, fid: u16) -> usize {
        if fid == EF_ALGO_INFO {
            self.push((EF_ALGO_INFO & 0xff) as u8);
            self.push(0x82);
            let lp = self.pos;
            self.pos += 2;
            const SIG: &[&[u8]] = &[
                ATTR_RSA1K,
                ATTR_RSA2K,
                ATTR_RSA3K,
                ATTR_RSA4K,
                ATTR_P256K1,
                ATTR_P256R1,
                ATTR_P384R1,
                ATTR_P521R1,
                ATTR_ED25519,
                ATTR_ED448,
            ];
            const DEC: &[&[u8]] = &[
                ATTR_RSA1K,
                ATTR_RSA2K,
                ATTR_RSA3K,
                ATTR_RSA4K,
                ATTR_P256K1,
                ATTR_P256R1,
                ATTR_P384R1,
                ATTR_P521R1,
                ATTR_CV25519,
                ATTR_X448,
            ];
            const AUT: &[&[u8]] = &[
                ATTR_RSA1K,
                ATTR_RSA2K,
                ATTR_RSA3K,
                ATTR_RSA4K,
                ATTR_P256K1,
                ATTR_P256R1,
                ATTR_P384R1,
                ATTR_P521R1,
                ATTR_ED25519,
                ATTR_ED448,
            ];
            for a in SIG {
                self.parse_algo(a, EF_ALGO_SIG);
            }
            for a in DEC {
                self.parse_algo(a, EF_ALGO_DEC);
            }
            for a in AUT {
                self.parse_algo(a, EF_ALGO_AUT);
            }
            let lpdif = self.pos - lp - 2;
            self.out[lp] = (lpdif >> 8) as u8;
            self.out[lp + 1] = (lpdif & 0xff) as u8;
            lpdif + 4
        } else {
            // C1/C2/C3: the stored algorithm attributes, or rsa2k by default.
            let priv_fid = 0x1000 | fid;
            if !self.fs.has_data(priv_fid) {
                self.parse_algo(ATTR_RSA2K, fid)
            } else {
                let len = self.fs.size(priv_fid).unwrap_or(0);
                let mut d = 0;
                if self.pos > 0 {
                    self.push((fid & 0xff) as u8);
                    self.push((len & 0xff) as u8);
                    d += 2;
                }
                self.read_flash(priv_fid);
                d + len
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::full_aid;
    use rsk_fs::Fs;
    use rsk_fs::storage::ram::RamStorage;

    fn fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    #[test]
    fn algo_default_is_rsa2k() {
        let mut fs = fs();
        let aid = full_aid(&[1, 2, 3, 4]);
        let mut out = [0u8; 64];
        let n = {
            let mut w = DoWriter::new(&mut out, &mut fs, &aid);
            w.build(EF_ALGO_SIG)
        };
        // parse_algo always self-writes the tag + length (C1 06) ahead of the
        // value; GET DATA strips the outer tag for FUNC DOs.
        assert_eq!(
            &out[..n],
            &[0xC1, 6, ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00]
        );
    }

    #[test]
    fn full_aid_is_returned_with_serial() {
        let mut fs = fs();
        let aid = full_aid(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut out = [0u8; 64];
        let n = {
            let mut w = DoWriter::new(&mut out, &mut fs, &aid);
            w.build(EF_FULL_AID)
        };
        assert_eq!(n, 16);
        assert_eq!(&out[..6], OPENPGP_AID);
        assert_eq!(&out[10..14], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn app_data_is_constructed_6e_with_nested_aid_and_hist() {
        let mut fs = fs();
        let aid = full_aid(&[1, 2, 3, 4]);
        let mut out = [0u8; 512];
        let n = {
            let mut w = DoWriter::new(&mut out, &mut fs, &aid);
            w.build(EF_APP_DATA)
        };
        // 6E 82 HH LL ...
        assert_eq!(out[0], 0x6E);
        assert_eq!(out[1], 0x82);
        let nested = ((out[2] as usize) << 8) | out[3] as usize;
        assert_eq!(n, nested + 4);
        // first nested DO is 4F (full AID), len 16.
        assert_eq!(out[4], 0x4F);
        assert_eq!(out[5], 16);
        assert_eq!(&out[6..12], OPENPGP_AID);
        // 5F52 historical bytes follows.
        let hist_tag = 6 + 16;
        assert_eq!(&out[hist_tag..hist_tag + 2], &[0x5F, 0x52]);
    }

    #[test]
    fn discrete_do_nests_algo_pw_fp() {
        let mut fs = fs();
        // seed a PW status so parse_pw_status emits its 7 bytes.
        fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
        let aid = full_aid(&[0; 4]);
        let mut out = [0u8; 512];
        let n = {
            let mut w = DoWriter::new(&mut out, &mut fs, &aid);
            w.build(EF_DISCRETE_DO)
        };
        assert_eq!(out[0], 0x73);
        assert_eq!(out[1], 0x82);
        assert!(n > 4);
        // C0 (ext caps) is the first nested DO.
        assert_eq!(out[4], 0xC0);
        assert_eq!(out[5], 10);
    }
}
