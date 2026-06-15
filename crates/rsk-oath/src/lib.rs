// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! YKOATH applet — Yubico's OATH protocol over CCID: a credential store of HMAC
//! keys (SHA-1/SHA-256/SHA-512), CALCULATE / CALCULATE ALL for TOTP/HOTP, an
//! optional access code, and the Nitrokey OTP-PIN / password-safe extensions.

#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;

use rsk_crypto::{Device, hmac_sha1, hmac_sha256, hmac_sha512};
use rsk_fs::{Fs, Storage};
use rsk_sdk::tlv::{find_tag, format_len};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// YKOATH applet AID.
pub const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Version reported in the SELECT response — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`]. ykman gates protocol features (rename, touch)
/// on this; the full 5.x set is implemented.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Random-byte source for the VALIDATE challenge. Same shape as
/// `rsk_openpgp::Rng`; the firmware TRNG wrapper implements both.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Outcome of a touch request (credentials stored with `PROP_TOUCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    Timeout,
    Declined,
}

/// Physical user presence; the firmware backs this with the BOOTSEL button
/// (same shape as `rsk_openpgp::UserPresence`).
pub trait UserPresence {
    fn request(&mut self) -> Presence;
}

/// Test/no-button stand-in: confirms instantly.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self) -> Presence {
        Presence::Confirmed
    }
}

// FIDs.
const EF_OATH_CRED: u16 = 0xBA00; // 255 slots, 0xBA00..=0xBAFE
const EF_OATH_CODE: u16 = 0xBAFF;
const EF_OTP_PIN: u16 = 0x10A0;

const MAX_OATH_CRED: u16 = 255;
const CHALLENGE_LEN: usize = 8;
const MAX_OTP_COUNTER: u8 = 3;

// Data-object tags.
const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
const TAG_NO_RESPONSE: u8 = 0x77;
const TAG_PROPERTY: u8 = 0x78;
const TAG_T_VERSION: u8 = 0x79;
const TAG_IMF: u8 = 0x7A;
const TAG_ALGO: u8 = 0x7B;
const TAG_TOUCH_RESPONSE: u8 = 0x7C;
const TAG_PASSWORD: u8 = 0x80;
const TAG_NEW_PASSWORD: u8 = 0x81;
const TAG_PWS_LOGIN: u8 = 0x83;
const TAG_PWS_PASSWORD: u8 = 0x84;
const TAG_PWS_METADATA: u8 = 0x85;

const ALG_HMAC_SHA1: u8 = 0x01;
const ALG_HMAC_SHA256: u8 = 0x02;
const ALG_HMAC_SHA512: u8 = 0x03;
const ALG_MASK: u8 = 0x0F;

const OATH_TYPE_HOTP: u8 = 0x10;
const OATH_TYPE_MASK: u8 = 0xF0;

const PROP_TOUCH: u8 = 0x02;

// Instructions.
const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALC_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;
const INS_VERIFY_CODE: u8 = 0xB1;
const INS_VERIFY_PIN: u8 = 0xB2;
const INS_CHANGE_PIN: u8 = 0xB3;
const INS_SET_PIN: u8 = 0xB4;
const INS_GET_CREDENTIAL: u8 = 0xB5;

/// "Wrong data" in this protocol is reported as `0x6700` (wrong length), which
/// is what clients expect.
const SW_WRONG_DATA: Sw = Sw::WRONG_LENGTH;

/// Max stored credential blob. Bounds the PUT/RENAME rebuild buffers and every
/// slot read; comfortably above anything real clients send (name ≤64, key ≤66,
/// three password-safe fields ≤255 each).
const CRED_MAX: usize = 1024;

pub struct OathApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned. OATH stores nothing under kbase today;
    /// wired anyway so every applet shares one derivation truth.
    otp_key: Option<[u8; 32]>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    /// Access-code session state. `true` when no code is set (everything
    /// allowed); with a code set, SELECT resets it and VALIDATE/VERIFY PIN
    /// flip it back.
    validated: bool,
    /// Challenge the host must answer in VALIDATE; regenerated on SELECT and
    /// SET CODE.
    challenge: [u8; CHALLENGE_LEN],
}

impl<'a> OathApplet<'a> {
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        Self {
            serial_id,
            serial_hash,
            otp_key,
            rng,
            presence,
            validated: true,
            challenge: [0; CHALLENGE_LEN],
        }
    }

    fn device(&self) -> Device<'_> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        }
    }

    /// First 8 chars of the serial hex string — the device id ykman salts its
    /// PBKDF2 access-code derivation with.
    fn serial_name(&self) -> [u8; 8] {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = [0u8; 8];
        for (i, b) in self.serial_id[..4].iter().enumerate() {
            out[2 * i] = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0xF) as usize];
        }
        out
    }

    fn cmd_put<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        let (mut name, mut key, mut imf, mut prop) = (None, None, None, None);
        for (t, v) in PutIter::new(data) {
            match t {
                TAG_NAME if name.is_none() => name = Some(v),
                TAG_KEY if key.is_none() => key = Some(v),
                TAG_IMF if imf.is_none() => imf = Some(v),
                TAG_PROPERTY if prop.is_none() => prop = v.first().copied(),
                _ => {}
            }
        }
        let Some(key) = key else {
            return Sw::INCORRECT_PARAMS;
        };
        // key = [type|alg, digits, secret…]; must hold at least those 2 bytes.
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        let Some(name) = name else {
            return Sw::INCORRECT_PARAMS;
        };
        let hotp = key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP;

        // Rebuild in normalised form: NAME, KEY, PROPERTY as a real TLV, other
        // TLVs verbatim, and (HOTP) the IMF last, zero-padded to 8 bytes.
        let mut blob = [0u8; CRED_MAX];
        let mut n = 0;
        let mut ok = emit_tlv(&mut blob, &mut n, TAG_NAME, name);
        ok &= emit_tlv(&mut blob, &mut n, TAG_KEY, key);
        if let Some(p) = prop {
            ok &= emit_tlv(&mut blob, &mut n, TAG_PROPERTY, &[p]);
        }
        for (t, v) in PutIter::new(data) {
            match t {
                TAG_NAME | TAG_KEY | TAG_IMF | TAG_PROPERTY => {}
                _ => ok &= emit_tlv(&mut blob, &mut n, t, v),
            }
        }
        if hotp {
            let mut counter = [0u8; 8];
            match imf {
                // Short IMF values are left-padded (ykman sends 4 bytes).
                Some(v) if v.len() <= 8 => counter[8 - v.len()..].copy_from_slice(v),
                Some(v) => counter.copy_from_slice(&v[..8]),
                None => {}
            }
            ok &= emit_tlv(&mut blob, &mut n, TAG_IMF, &counter);
        } else if let Some(v) = imf {
            ok &= emit_tlv(&mut blob, &mut n, TAG_IMF, v);
        }
        if !ok {
            return Sw::FILE_FULL;
        }

        let mut scratch = [0u8; CRED_MAX];
        let fid = match find_cred(fs, name, &mut scratch) {
            Some((fid, _)) => fid,
            None => match free_slot(fs) {
                Some(fid) => fid,
                None => return Sw::FILE_FULL,
            },
        };
        match fs.put(fid, &blob[..n]) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    fn cmd_delete<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(name) = find_tag(&apdu.data[..apdu.nc], TAG_NAME as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut scratch = [0u8; CRED_MAX];
        match find_cred(fs, name, &mut scratch) {
            Some((fid, _)) => {
                let _ = fs.delete(fid);
                Sw::OK
            }
            None => Sw::DATA_INVALID,
        }
    }

    fn cmd_set_code<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.is_empty() {
            let _ = fs.delete(EF_OATH_CODE);
            self.validated = true;
            return Sw::OK;
        }
        let Some(key) = find_tag(data, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.is_empty() {
            let _ = fs.delete(EF_OATH_CODE);
            self.validated = true;
            return Sw::OK;
        }
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(resp) = find_tag(data, TAG_RESPONSE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        // The host proves it knows the new code: response = HMAC(key, challenge).
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(key[0], &key[1..], chal, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        if !ct_eq(resp, &mac[..size]) {
            return Sw::DATA_INVALID;
        }
        self.rng.borrow_mut().fill(&mut self.challenge);
        if fs.put(EF_OATH_CODE, key).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        self.validated = false;
        Sw::OK
    }

    fn cmd_reset<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.p1 != 0xDE || apdu.p2 != 0xAD {
            return Sw::INCORRECT_P1P2;
        }
        let mut fids = [0u16; MAX_OATH_CRED as usize];
        let n = present_creds(fs, &mut fids);
        for &fid in &fids[..n] {
            let _ = fs.delete(fid);
        }
        let _ = fs.delete(EF_OATH_CODE);
        let _ = fs.delete(EF_OTP_PIN);
        self.validated = true;
        Sw::OK
    }

    fn cmd_list<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // Extended list (nitropy): one data byte 0x01 appends a properties byte.
        let ext = apdu.nc == 1 && apdu.data[0] == 0x01;
        let mut fids = [0u16; MAX_OATH_CRED as usize];
        let nfids = present_creds(fs, &mut fids);
        let mut scratch = [0u8; CRED_MAX];
        for &fid in &fids[..nfids] {
            let Some(n) = fs.read(fid, &mut scratch) else {
                continue;
            };
            let blob = &scratch[..n.min(CRED_MAX)];
            let (Some(name), Some(key)) = (
                find_tag(blob, TAG_NAME as u16),
                find_tag(blob, TAG_KEY as u16),
            ) else {
                continue;
            };
            if key.is_empty() || name.len() + 2 > 255 {
                continue;
            }
            let entry = 2 + 1 + name.len() + ext as usize;
            if res.len() + entry > res.capacity() {
                break;
            }
            res.push(TAG_NAME_LIST);
            res.push((name.len() + 1 + ext as usize) as u8);
            res.push(key[0]);
            res.extend(name);
            if ext {
                let mut props = 0u8;
                if find_tag(blob, TAG_PWS_LOGIN as u16).is_some()
                    || find_tag(blob, TAG_PWS_PASSWORD as u16).is_some()
                    || find_tag(blob, TAG_PWS_METADATA as u16).is_some()
                {
                    props |= 0x4;
                }
                if find_tag(blob, TAG_PROPERTY as u16)
                    .and_then(|v| v.first())
                    .is_some_and(|p| p & PROP_TOUCH != 0)
                {
                    props |= 0x1;
                }
                res.push(props);
            }
        }
        Sw::OK
    }

    fn cmd_validate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let data = &apdu.data[..apdu.nc];
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(resp) = find_tag(data, TAG_RESPONSE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut code = [0u8; 128];
        let Some(n) = fs.read(EF_OATH_CODE, &mut code) else {
            self.validated = true;
            return Sw::DATA_INVALID;
        };
        let code = &code[..n.min(128)];
        if code.is_empty() {
            self.validated = true;
            return Sw::DATA_INVALID;
        }
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(code[0], &code[1..], &self.challenge, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        if !ct_eq(resp, &mac[..size]) {
            return Sw::DATA_INVALID;
        }
        // Mutual authentication: answer the host's challenge with the same key.
        let Some(size) = oath_hmac(code[0], &code[1..], chal, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        self.validated = true;
        res.push(TAG_RESPONSE);
        res.push(size as u8);
        res.extend(&mac[..size]);
        Sw::OK
    }

    fn cmd_calculate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p2 != 0x00 && apdu.p2 != 0x01 {
            return Sw::INCORRECT_P1P2;
        }
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(name) = find_tag(data, TAG_NAME as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut scratch = [0u8; CRED_MAX];
        let Some((fid, n)) = find_cred(fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n];
        let Some(key) = find_tag(blob, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        // Touch-flagged credentials compute only after a confirmed press —
        // gated here, before the HOTP counter burns.
        if find_tag(blob, TAG_PROPERTY as u16)
            .and_then(|v| v.first())
            .is_some_and(|p| p & PROP_TOUCH != 0)
            && self.presence.borrow_mut().request() != Presence::Confirmed
        {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let hotp = key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP;
        // HOTP ignores the host challenge: the stored 8-byte counter is the
        // moving factor.
        let imf = if hotp {
            match find_tag_range(blob, TAG_IMF) {
                Some(r) if r.len() >= 8 => Some(r),
                _ => return Sw::INCORRECT_PARAMS,
            }
        } else {
            None
        };
        res.push(TAG_RESPONSE + apdu.p2);
        let chal_eff = match &imf {
            Some(r) => &blob[r.start..r.start + 8],
            None => chal,
        };
        if calculate(apdu.p2 == 0x01, key, chal_eff, res).is_none() {
            return Sw::EXEC_ERROR;
        }
        if let Some(r) = imf {
            // Bump the counter and persist the updated blob.
            let mut counter = [0u8; 8];
            counter.copy_from_slice(&scratch[r.start..r.start + 8]);
            let v = u64::from_be_bytes(counter).wrapping_add(1);
            scratch[r.start..r.start + 8].copy_from_slice(&v.to_be_bytes());
            if fs.put(fid, &scratch[..n]).is_err() {
                return Sw::MEMORY_FAILURE;
            }
        }
        Sw::OK
    }

    fn cmd_calculate_all<S: Storage>(
        &mut self,
        apdu: &Apdu,
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p2 != 0x00 && apdu.p2 != 0x01 {
            return Sw::INCORRECT_P1P2;
        }
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(chal) = find_tag(&apdu.data[..apdu.nc], TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut fids = [0u16; MAX_OATH_CRED as usize];
        let nfids = present_creds(fs, &mut fids);
        let mut scratch = [0u8; CRED_MAX];
        for &fid in &fids[..nfids] {
            let Some(n) = fs.read(fid, &mut scratch) else {
                continue;
            };
            let blob = &scratch[..n.min(CRED_MAX)];
            let (Some(name), Some(key)) = (
                find_tag(blob, TAG_NAME as u16),
                find_tag(blob, TAG_KEY as u16),
            ) else {
                continue;
            };
            if key.len() < 2 || name.len() > 255 {
                continue;
            }
            // Worst-case entry: name TLV + full-response TLV (64 + digits).
            if res.len() + 2 + name.len() + 2 + 65 > res.capacity() {
                break;
            }
            res.push(TAG_NAME);
            res.push(name.len() as u8);
            res.extend(name);
            if key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP {
                // HOTP is never computed in bulk (it would burn counters).
                res.push(TAG_NO_RESPONSE);
                res.push(1);
                res.push(key[1]);
            } else if find_tag(blob, TAG_PROPERTY as u16)
                .and_then(|v| v.first())
                .is_some_and(|p| p & PROP_TOUCH != 0)
            {
                res.push(TAG_TOUCH_RESPONSE);
                res.push(1);
                res.push(key[1]);
            } else {
                res.push(TAG_RESPONSE + apdu.p2);
                if calculate(apdu.p2 == 0x01, key, chal, res).is_none() {
                    // Unknown algorithm: emit the digits byte only.
                    res.push(1);
                    res.push(key[1]);
                }
            }
        }
        Sw::OK
    }

    fn cmd_verify_code<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let data = &apdu.data[..apdu.nc];
        if find_tag(data, TAG_NAME as u16).is_none() {
            return Sw::INCORRECT_PARAMS;
        }
        // The named credential is ignored — slot 0 is always the one verified.
        let mut scratch = [0u8; CRED_MAX];
        let Some(n) = fs.read(EF_OATH_CRED, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n.min(CRED_MAX)];
        let Some(key) = find_tag(blob, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        if key[0] & OATH_TYPE_MASK != OATH_TYPE_HOTP {
            return Sw::DATA_INVALID;
        }
        let Some(imf) = find_tag(blob, TAG_IMF as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if imf.len() < 8 {
            return Sw::INCORRECT_PARAMS;
        }
        let code_int = match find_tag(data, TAG_RESPONSE as u16) {
            Some(v) if v.len() >= 4 => u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            Some(_) => return Sw::INCORRECT_PARAMS,
            None => 0,
        };
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(key[0], &key[2..], &imf[..8], &mut mac) else {
            return Sw::EXEC_ERROR;
        };
        let off = (mac[size - 1] & 0xF) as usize;
        let trunc = u32::from_be_bytes([mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]]);
        let modulus = if key[1] == 6 { 1_000_000 } else { 100_000_000 };
        if trunc % modulus != code_int {
            return SW_WRONG_DATA;
        }
        Sw::OK
    }

    fn cmd_rename<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.first() != Some(&TAG_NAME) {
            return SW_WRONG_DATA;
        }
        // Two TAG_NAME TLVs back to back: current name, then the new one.
        let mut names = PutIter::new(data).filter(|(t, _)| *t == TAG_NAME);
        let (Some((_, name)), Some((_, new_name))) = (names.next(), names.next()) else {
            return SW_WRONG_DATA;
        };
        if name == new_name {
            return SW_WRONG_DATA;
        }
        let mut scratch = [0u8; CRED_MAX];
        let Some((fid, n)) = find_cred(fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        // Rebuild the blob with the name TLV replaced in place.
        let mut blob = [0u8; CRED_MAX];
        let mut bn = 0;
        let mut replaced = false;
        let mut ok = true;
        for (t, v) in rsk_sdk::tlv::Tlv::new(&scratch[..n]) {
            if t == TAG_NAME as u16 && !replaced {
                ok &= emit_tlv(&mut blob, &mut bn, TAG_NAME, new_name);
                replaced = true;
            } else {
                ok &= emit_tlv(&mut blob, &mut bn, t as u8, v);
            }
        }
        if !ok {
            return Sw::FILE_FULL;
        }
        match fs.put(fid, &blob[..bn]) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    fn cmd_get_credential<S: Storage>(
        &mut self,
        apdu: &Apdu,
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        // Gated on validation: this returns stored password-safe secrets.
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.len() < 3 {
            return Sw::INCORRECT_PARAMS;
        }
        if data[0] != TAG_NAME {
            return SW_WRONG_DATA;
        }
        let Some(name) = find_tag(data, TAG_NAME as u16) else {
            return SW_WRONG_DATA;
        };
        let mut scratch = [0u8; CRED_MAX];
        let Some((_, n)) = find_cred(fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n];
        for tag in [
            TAG_NAME,
            TAG_PWS_LOGIN,
            TAG_PWS_PASSWORD,
            TAG_PWS_METADATA,
            TAG_PROPERTY,
        ] {
            if let Some(v) = find_tag(blob, tag as u16)
                && v.len() <= 255
                && res.len() + 2 + v.len() <= res.capacity()
            {
                res.push(tag);
                res.push(v.len() as u8);
                res.extend(v);
            }
        }
        Sw::OK
    }

    fn cmd_set_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if fs.has_data(EF_OTP_PIN) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(pw) = find_tag(&apdu.data[..apdu.nc], TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut rec = [0u8; 33];
        rec[0] = MAX_OTP_COUNTER;
        rec[1..].copy_from_slice(&self.device().double_hash_pin(pw));
        match fs.put(EF_OTP_PIN, &rec) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    fn cmd_change_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let mut rec = [0u8; 33];
        if fs.read(EF_OTP_PIN, &mut rec) != Some(33) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        let Some(pw) = find_tag(data, TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if !ct_eq(&self.device().double_hash_pin(pw), &rec[1..]) {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(new_pw) = find_tag(data, TAG_NEW_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        rec[0] = MAX_OTP_COUNTER;
        rec[1..].copy_from_slice(&self.device().double_hash_pin(new_pw));
        match fs.put(EF_OTP_PIN, &rec) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    fn cmd_verify_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let mut rec = [0u8; 33];
        if fs.read(EF_OTP_PIN, &mut rec) != Some(33) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(pw) = find_tag(&apdu.data[..apdu.nc], TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let hash = self.device().double_hash_pin(pw);
        // A counter at 0 fails even with the right PIN (CHANGE PIN still works).
        if rec[0] == 0 || !ct_eq(&hash, &rec[1..]) {
            rec[0] = rec[0].saturating_sub(1);
            let _ = fs.put(EF_OTP_PIN, &rec);
            self.validated = false;
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        rec[0] = MAX_OTP_COUNTER;
        let _ = fs.put(EF_OTP_PIN, &rec);
        // The OTP PIN doubles as an alternative to VALIDATE (nitropy flow).
        self.validated = true;
        Sw::OK
    }
}

impl<S: Storage> Applet<Fs<S>> for OathApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        OATH_AID
    }

    /// SELECT response: version + device id, plus a fresh challenge (and its
    /// algorithm) when an access code is set.
    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        res.push(TAG_T_VERSION);
        res.push(3);
        res.push(maj);
        res.push(min);
        res.push(patch);
        res.push(TAG_NAME);
        res.push(8);
        res.extend(&self.serial_name());
        let code_set = fs.has_data(EF_OATH_CODE);
        if code_set {
            self.rng.borrow_mut().fill(&mut self.challenge);
            res.push(TAG_CHALLENGE);
            res.push(CHALLENGE_LEN as u8);
            res.extend(&self.challenge);
            res.push(TAG_ALGO);
            res.push(1);
            res.push(ALG_HMAC_SHA1);
        }
        // With a code set, every new SELECT must start locked: protected
        // commands work only after VALIDATE (or VERIFY PIN).
        self.validated = !code_set;
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_PUT => self.cmd_put(apdu, fs),
            INS_DELETE => self.cmd_delete(apdu, fs),
            INS_SET_CODE => self.cmd_set_code(apdu, fs),
            INS_RESET => self.cmd_reset(apdu, fs),
            INS_RENAME => self.cmd_rename(apdu, fs),
            INS_LIST => self.cmd_list(apdu, fs, res),
            INS_CALCULATE => self.cmd_calculate(apdu, fs, res),
            INS_VALIDATE => self.cmd_validate(apdu, fs, res),
            INS_CALC_ALL => self.cmd_calculate_all(apdu, fs, res),
            // Responses fit one CCID block; nothing is ever left pending.
            INS_SEND_REMAINING => Sw::OK,
            INS_VERIFY_CODE => self.cmd_verify_code(apdu, fs),
            INS_VERIFY_PIN => self.cmd_verify_otp_pin(apdu, fs),
            INS_CHANGE_PIN => self.cmd_change_otp_pin(apdu, fs),
            INS_SET_PIN => self.cmd_set_otp_pin(apdu, fs),
            INS_GET_CREDENTIAL => self.cmd_get_credential(apdu, fs, res),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// HMAC with the credential's algorithm nibble; returns the digest size.
fn oath_hmac(alg: u8, key: &[u8], msg: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    match alg & ALG_MASK {
        ALG_HMAC_SHA1 => {
            out[..20].copy_from_slice(&hmac_sha1(key, msg));
            Some(20)
        }
        ALG_HMAC_SHA256 => {
            out[..32].copy_from_slice(&hmac_sha256(key, msg));
            Some(32)
        }
        ALG_HMAC_SHA512 => {
            out[..64].copy_from_slice(&hmac_sha512(key, msg));
            Some(64)
        }
        _ => None,
    }
}

/// Append `[len][digits][code]` to `res` — the RFC 4226 dynamic truncation
/// when `truncate`, the full HMAC otherwise. The caller has already pushed the
/// response tag. `key` = `[type|alg, digits, secret…]`.
fn calculate(truncate: bool, key: &[u8], chal: &[u8], res: &mut ResBuf) -> Option<()> {
    let mut mac = [0u8; 64];
    let size = oath_hmac(key[0], &key[2..], chal, &mut mac)?;
    if truncate {
        res.push(4 + 1);
        res.push(key[1]);
        let off = (mac[size - 1] & 0xF) as usize;
        res.push(mac[off] & 0x7F);
        res.push(mac[off + 1]);
        res.push(mac[off + 2]);
        res.push(mac[off + 3]);
    } else {
        res.push((size + 1) as u8);
        res.push(key[1]);
        res.extend(&mac[..size]);
    }
    Some(())
}

/// FIDs of every present OATH credential (slots `EF_OATH_CRED..`), gathered in a
/// single storage pass; returns the count written to `out`. Iterating these is
/// O(present). The old `for i in 0..MAX_OATH_CRED { fs.read/delete/has_data }`
/// probe was O(255·items): a read of an *absent* slot rescans all of flash, so
/// sweeping the whole 255-slot range cost tens of seconds on a busy store. See
/// the anti-pattern note on [`rsk_fs::Fs::for_each_key`].
fn present_creds<S: Storage>(fs: &mut Fs<S>, out: &mut [u16; MAX_OATH_CRED as usize]) -> usize {
    let mut n = 0;
    fs.for_each_key(&mut |fid| {
        if (EF_OATH_CRED..EF_OATH_CRED + MAX_OATH_CRED).contains(&fid) && n < out.len() {
            out[n] = fid;
            n += 1;
        }
    });
    // for_each_key yields storage order; sort to the old FID-order sweep so LIST /
    // CALCULATE ALL responses stay byte-identical to the previous behavior.
    out[..n].sort_unstable();
    n
}

/// Find a present credential whose `TAG_NAME` equals `name`; the blob is left in
/// `buf`. Only present slots are read (see [`present_creds`]).
fn find_cred<S: Storage>(fs: &mut Fs<S>, name: &[u8], buf: &mut [u8]) -> Option<(u16, usize)> {
    let mut fids = [0u16; MAX_OATH_CRED as usize];
    let nfids = present_creds(fs, &mut fids);
    for &fid in &fids[..nfids] {
        if let Some(n) = fs.read(fid, buf) {
            let n = n.min(buf.len());
            if find_tag(&buf[..n], TAG_NAME as u16) == Some(name) {
                return Some((fid, n));
            }
        }
    }
    None
}

fn free_slot<S: Storage>(fs: &mut Fs<S>) -> Option<u16> {
    let mut used = [false; MAX_OATH_CRED as usize];
    fs.for_each_key(&mut |fid| {
        let Some(i) = fid.checked_sub(EF_OATH_CRED) else {
            return;
        };
        if (i as usize) < used.len() {
            used[i as usize] = true;
        }
    });
    used.iter()
        .position(|&u| !u)
        .map(|i| EF_OATH_CRED + i as u16)
}

/// Byte range of the first `tag` value inside `blob` (so callers can mutate it
/// in place — the HOTP counter bump).
fn find_tag_range(blob: &[u8], tag: u8) -> Option<core::ops::Range<usize>> {
    let mut i = 0;
    while i < blob.len() {
        let t = *blob.get(i)?;
        i += 1;
        let l0 = *blob.get(i)?;
        i += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*blob.get(i)? as usize) << 8) | *blob.get(i + 1)? as usize;
                i += 2;
                v
            }
            0x81 => {
                let v = *blob.get(i)? as usize;
                i += 1;
                v
            }
            n => n as usize,
        };
        let end = i.checked_add(len)?;
        if end > blob.len() {
            return None;
        }
        if t == tag {
            return Some(i..end);
        }
        i = end;
    }
    None
}

/// TLV walk over PUT data. `TAG_PROPERTY` is special-cased per the YKOATH spec:
/// a bare `(tag, value)` byte pair with no length octet (ykman sends exactly
/// that). Everything else is a normal BER-TLV. Malformed input ends iteration.
struct PutIter<'d> {
    rest: &'d [u8],
}

impl<'d> PutIter<'d> {
    fn new(data: &'d [u8]) -> Self {
        Self { rest: data }
    }
}

impl<'d> Iterator for PutIter<'d> {
    type Item = (u8, &'d [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.rest;
        let t = *b.first()?;
        if t == TAG_PROPERTY {
            let v = b.get(1..2)?;
            self.rest = &b[2..];
            return Some((t, v));
        }
        let mut p = 1;
        let l0 = *b.get(p)?;
        p += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*b.get(p)? as usize) << 8) | *b.get(p + 1)? as usize;
                p += 2;
                v
            }
            0x81 => {
                let v = *b.get(p)? as usize;
                p += 1;
                v
            }
            n => n as usize,
        };
        let end = p.checked_add(len)?;
        if end > b.len() {
            return None;
        }
        let v = &b[p..end];
        self.rest = &b[end..];
        Some((t, v))
    }
}

/// Append a BER-TLV to `buf`; `false` on overflow.
fn emit_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) -> bool {
    if val.len() > u16::MAX as usize {
        return false;
    }
    let mut lenb = [0u8; 3];
    let ln = format_len(val.len() as u16, &mut lenb);
    if *n + 1 + ln + val.len() > buf.len() {
        return false;
    }
    buf[*n] = tag;
    buf[*n + 1..*n + 1 + ln].copy_from_slice(&lenb[..ln]);
    buf[*n + 1 + ln..*n + 1 + ln + val.len()].copy_from_slice(val);
    *n += 1 + ln + val.len();
    true
}

/// Constant-time equality — the access-code MAC compare must not be a timing
/// oracle, and short responses must never match.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    /// RFC 6238 reference secrets.
    const SECRET_SHA1: &[u8] = b"12345678901234567890";
    const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    struct CountRng(u8);
    impl Rng for CountRng {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                *x = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// Answers every touch request with a fixed outcome and counts the asks.
    struct StubPresence(Presence, u32);
    impl UserPresence for StubPresence {
        fn request(&mut self) -> Presence {
            self.1 += 1;
            self.0
        }
    }

    const SERIAL: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];

    fn new_fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    fn select(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::select(app, false, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    fn run(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 2048];
        let mut res = ResBuf::new(&mut out);
        let apdu = Apdu::parse(raw).unwrap();
        let sw = Applet::process(app, &apdu, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 256);
        let mut v = vec![0x00, ins, p1, p2];
        if !data.is_empty() {
            v.push(data.len() as u8);
            v.extend_from_slice(data);
        }
        v
    }

    fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        assert!(val.len() < 128);
        let mut v = vec![tag, val.len() as u8];
        v.extend_from_slice(val);
        v
    }

    /// PUT data the way ykman builds it: NAME and KEY TLVs, the property as a
    /// bare byte pair, the IMF as a 4-byte TLV.
    fn put_data(
        name: &[u8],
        ty_alg: u8,
        digits: u8,
        secret: &[u8],
        touch: bool,
        imf: Option<u32>,
    ) -> Vec<u8> {
        let mut d = tlv(TAG_NAME, name);
        let mut key = vec![ty_alg, digits];
        key.extend_from_slice(secret);
        d.extend(tlv(TAG_KEY, &key));
        if touch {
            d.extend([TAG_PROPERTY, PROP_TOUCH]);
        }
        if let Some(c) = imf {
            d.extend(tlv(TAG_IMF, &c.to_be_bytes()));
        }
        d
    }

    fn put(app: &mut OathApplet, fs: &mut Fs<RamStorage>, data: &[u8]) -> Sw {
        run(app, fs, &apdu(INS_PUT, 0, 0, data)).0
    }

    /// CALCULATE and decode the truncated decimal code.
    fn calc_code(
        app: &mut OathApplet,
        fs: &mut Fs<RamStorage>,
        name: &[u8],
        challenge: u64,
        digits: u32,
    ) -> u32 {
        let mut d = tlv(TAG_CHALLENGE, &challenge.to_be_bytes());
        d.extend(tlv(TAG_NAME, name));
        let (sw, body) = run(app, fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
        assert_eq!(sw, Sw::OK);
        // [tag=0x76][len=5][digits][4-byte code]
        assert_eq!(body[0], TAG_RESPONSE + 1);
        assert_eq!(body[1], 5);
        let v = u32::from_be_bytes([body[3], body[4], body[5], body[6]]);
        v % 10u32.pow(digits)
    }

    #[test]
    fn select_reports_version_and_serial() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let (sw, body) = select(&mut app, &mut fs);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&body[..5], &[TAG_T_VERSION, 3, 5, 7, 4]);
        assert_eq!(body[5], TAG_NAME);
        assert_eq!(body[6], 8);
        assert_eq!(&body[7..15], b"12345678");
        // No access code: no challenge TLV, applet usable straight away.
        assert_eq!(body.len(), 15);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn totp_rfc6238_vectors() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // RFC 6238 appendix B, time 59 s → T = 1, 8 digits.
        for (name, alg, secret, code) in [
            (b"sha1".as_slice(), ALG_HMAC_SHA1, SECRET_SHA1, 94287082u32),
            (b"sha256", ALG_HMAC_SHA256, SECRET_SHA256, 46119246),
            (b"sha512", ALG_HMAC_SHA512, SECRET_SHA512, 90693936),
        ] {
            assert_eq!(
                put(
                    &mut app,
                    &mut fs,
                    &put_data(name, 0x20 | alg, 8, secret, false, None)
                ),
                Sw::OK
            );
            assert_eq!(calc_code(&mut app, &mut fs, name, 1, 8), code);
        }
    }

    #[test]
    fn totp_full_response() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"t", 0x21, 6, SECRET_SHA1, false, None),
        );
        let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        d.extend(tlv(TAG_NAME, b"t"));
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x00, &d));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[0], TAG_RESPONSE);
        assert_eq!(body[1], 21); // digits byte + full SHA-1 HMAC
        assert_eq!(body[2], 6);
        assert_eq!(&body[3..23], &hmac_sha1(SECRET_SHA1, &1u64.to_be_bytes()));
    }

    #[test]
    fn hotp_rfc4226_sequence_and_counter_persistence() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // No IMF sent → counter starts at 0 (RFC 4226 appendix D, 6 digits).
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None),
        );
        for code in [755224u32, 287082, 359152] {
            // The host challenge is ignored for HOTP.
            assert_eq!(calc_code(&mut app, &mut fs, b"h", 0xDEAD, 6), code);
        }
        // A fresh applet over the same storage continues the sequence.
        let mut app2 = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(calc_code(&mut app2, &mut fs, b"h", 0, 6), 969429);
    }

    #[test]
    fn hotp_imf_padded_and_honoured() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // ykman sends the initial counter as 4 bytes; stored padded to 8.
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, Some(5)),
        );
        assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 254676); // count 5
        assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 287922); // count 6
    }

    #[test]
    fn calculate_touch_cred_requires_press() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        // HOTP: a denied attempt must also leave the counter unburnt.
        let deny = RefCell::new(StubPresence(Presence::Timeout, 0));
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, true, None),
        );
        let mut d = tlv(TAG_CHALLENGE, &0u64.to_be_bytes());
        d.extend(tlv(TAG_NAME, b"h"));
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        assert!(body.is_empty());
        assert_eq!(deny.borrow().1, 1);
        // Confirmed press → the counter-0 code: the denied try burned nothing.
        let confirm = RefCell::new(StubPresence(Presence::Confirmed, 0));
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &confirm);
        assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 755224);
        assert_eq!(confirm.borrow().1, 1);
    }

    #[test]
    fn calculate_plain_cred_never_asks_for_touch() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let deny = RefCell::new(StubPresence(Presence::Declined, 0));
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
        put(
            &mut app,
            &mut fs,
            &put_data(b"t", 0x21, 8, SECRET_SHA1, false, None),
        );
        assert_eq!(calc_code(&mut app, &mut fs, b"t", 1, 8), 94287082);
        assert_eq!(deny.borrow().1, 0);
    }

    #[test]
    fn calculate_all_reports_touch_without_press() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let deny = RefCell::new(StubPresence(Presence::Timeout, 0));
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
        put(
            &mut app,
            &mut fs,
            &put_data(b"t", 0x21, 6, SECRET_SHA1, true, None),
        );
        let d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &d));
        assert_eq!(sw, Sw::OK);
        // Touch creds are reported (0x7C), never computed, no button involved.
        let expect = [tlv(TAG_NAME, b"t"), vec![TAG_TOUCH_RESPONSE, 1, 6]].concat();
        assert_eq!(body, expect);
        assert_eq!(deny.borrow().1, 0);
    }

    #[test]
    fn put_validates_key_and_name() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // Missing key.
        assert_eq!(
            put(&mut app, &mut fs, &tlv(TAG_NAME, b"x")),
            Sw::INCORRECT_PARAMS
        );
        // Missing name.
        assert_eq!(
            put(&mut app, &mut fs, &tlv(TAG_KEY, &[0x21, 6, 1, 2])),
            Sw::INCORRECT_PARAMS
        );
        // Key shorter than [type, digits] is rejected.
        let mut d = tlv(TAG_NAME, b"x");
        d.extend(tlv(TAG_KEY, &[0x21]));
        assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS);
    }

    #[test]
    fn put_overwrites_same_name() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"a", 0x21, 6, b"oldkey-0123456789", false, None),
        );
        put(
            &mut app,
            &mut fs,
            &put_data(b"a", 0x21, 8, SECRET_SHA1, false, None),
        );
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
        // One entry only, and CALCULATE uses the new key/digits.
        assert_eq!(body, [vec![TAG_NAME_LIST, 2, 0x21], b"a".to_vec()].concat());
        assert_eq!(calc_code(&mut app, &mut fs, b"a", 1, 8), 94287082);
    }

    #[test]
    fn list_plain_and_extended() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"plain", 0x21, 6, SECRET_SHA1, false, None),
        );
        put(
            &mut app,
            &mut fs,
            &put_data(b"touchy", 0x22, 6, SECRET_SHA256, true, None),
        );
        let mut with_pws = put_data(b"pws", 0x21, 6, SECRET_SHA1, false, None);
        with_pws.extend(tlv(TAG_PWS_LOGIN, b"user"));
        put(&mut app, &mut fs, &with_pws);

        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
        let expect = [
            vec![TAG_NAME_LIST, 6, 0x21],
            b"plain".to_vec(),
            vec![TAG_NAME_LIST, 7, 0x22],
            b"touchy".to_vec(),
            vec![TAG_NAME_LIST, 4, 0x21],
            b"pws".to_vec(),
        ]
        .concat();
        assert_eq!(body, expect);

        // Extended form appends a properties byte: touch = 0x1, PWS data = 0x4.
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[0x01]));
        assert_eq!(sw, Sw::OK);
        let expect = [
            vec![TAG_NAME_LIST, 7, 0x21],
            b"plain".to_vec(),
            vec![0x0],
            vec![TAG_NAME_LIST, 8, 0x22],
            b"touchy".to_vec(),
            vec![0x1],
            vec![TAG_NAME_LIST, 5, 0x21],
            b"pws".to_vec(),
            vec![0x4],
        ]
        .concat();
        assert_eq!(body, expect);
    }

    #[test]
    fn delete_removes_credential() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"gone", 0x21, 6, SECRET_SHA1, false, None),
        );
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"gone")),
        );
        assert_eq!(sw, Sw::OK);
        let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert!(body.is_empty());
        // Deleting it again: unknown name.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"gone")),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
    }

    #[test]
    fn rename_replaces_name_in_place() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"old", 0x21, 8, SECRET_SHA1, false, None),
        );
        let mut d = tlv(TAG_NAME, b"old");
        d.extend(tlv(TAG_NAME, b"newname"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
        assert_eq!(sw, Sw::OK);
        // Old gone, new resolves and still calculates correctly.
        assert_eq!(calc_code(&mut app, &mut fs, b"newname", 1, 8), 94287082);
        let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        d.extend(tlv(TAG_NAME, b"old"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
        assert_eq!(sw, Sw::DATA_INVALID);

        // Same old/new name is rejected; unknown name is DATA_INVALID.
        let mut d = tlv(TAG_NAME, b"newname");
        d.extend(tlv(TAG_NAME, b"newname"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
        assert_eq!(sw, SW_WRONG_DATA);
        let mut d = tlv(TAG_NAME, b"missing");
        d.extend(tlv(TAG_NAME, b"other"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);
    }

    /// Drive the full access-code lifecycle the way ykman does.
    #[test]
    fn set_code_and_validate_flow() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"c", 0x21, 8, SECRET_SHA1, false, None),
        );
        let code_key = {
            let mut k = vec![ALG_HMAC_SHA1];
            k.extend_from_slice(&[0xAB; 16]);
            k
        };

        // SET CODE with a response that doesn't prove key knowledge.
        let mut d = tlv(TAG_KEY, &code_key);
        d.extend(tlv(TAG_CHALLENGE, &[1, 2, 3, 4, 5, 6, 7, 8]));
        d.extend(tlv(TAG_RESPONSE, &[0u8; 20]));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);

        // Correct proof: response = HMAC(key, challenge).
        let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let proof = hmac_sha1(&[0xAB; 16], &chal);
        let mut d = tlv(TAG_KEY, &code_key);
        d.extend(tlv(TAG_CHALLENGE, &chal));
        d.extend(tlv(TAG_RESPONSE, &proof));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &d));
        assert_eq!(sw, Sw::OK);

        // The session is immediately unvalidated, and so is a fresh SELECT.
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        let (sw, body) = select(&mut app, &mut fs);
        assert_eq!(sw, Sw::OK);
        // Challenge + algorithm TLVs are now present.
        let card_chal = find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec();
        assert_eq!(card_chal.len(), 8);
        assert_eq!(find_tag(&body, TAG_ALGO as u16), Some(&[ALG_HMAC_SHA1][..]));
        for ins in [
            INS_PUT,
            INS_DELETE,
            INS_LIST,
            INS_CALCULATE,
            INS_CALC_ALL,
            INS_RENAME,
        ] {
            let (sw, _) = run(&mut app, &mut fs, &apdu(ins, 0, 0, &[]));
            assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "ins {ins:#x}");
        }

        // VALIDATE with a wrong response stays locked…
        let host_chal = [9u8, 9, 9, 9, 8, 8, 8, 8];
        let mut d = tlv(TAG_CHALLENGE, &host_chal);
        d.extend(tlv(TAG_RESPONSE, &[0u8; 20]));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);
        // …and a truncated (1-byte) response must not brute-force its way in.
        let full = hmac_sha1(&[0xAB; 16], &card_chal);
        let mut d = tlv(TAG_CHALLENGE, &host_chal);
        d.extend(tlv(TAG_RESPONSE, &full[..1]));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);

        // Correct response unlocks and returns the mutual proof.
        let mut d = tlv(TAG_CHALLENGE, &host_chal);
        d.extend(tlv(TAG_RESPONSE, &full));
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
        assert_eq!(sw, Sw::OK);
        assert_eq!(
            find_tag(&body, TAG_RESPONSE as u16),
            Some(&hmac_sha1(&[0xAB; 16], &host_chal)[..])
        );
        assert_eq!(calc_code(&mut app, &mut fs, b"c", 1, 8), 94287082);

        // SET CODE with an empty key removes the code again.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[])),
        );
        assert_eq!(sw, Sw::OK);
        let (_, body) = select(&mut app, &mut fs);
        assert_eq!(find_tag(&body, TAG_CHALLENGE as u16), None);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn validate_without_code_reports_invalid() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let mut d = tlv(TAG_CHALLENGE, &[0; 8]);
        d.extend(tlv(TAG_RESPONSE, &[0; 20]));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);
        // But the applet stays usable — no access code is set.
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn reset_clears_creds_code_and_pin() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"a", 0x21, 6, SECRET_SHA1, false, None),
        );
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        );
        assert_eq!(sw, Sw::OK);

        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RESET, 0, 0, &[]));
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[]));
        assert_eq!(sw, Sw::OK);

        let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
        assert!(body.is_empty());
        // The OTP PIN file is gone — SET PIN works again.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678")),
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn otp_pin_set_change_verify_and_lockout() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // VERIFY/CHANGE before a PIN exists.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"x")),
        );
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        );
        assert_eq!(sw, Sw::OK);
        // SET PIN refuses to overwrite.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"x")),
        );
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        );
        assert_eq!(sw, Sw::OK);

        // CHANGE PIN with wrong then right old PIN.
        let mut d = tlv(TAG_PASSWORD, b"wrong");
        d.extend(tlv(TAG_NEW_PASSWORD, b"0000"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        let mut d = tlv(TAG_PASSWORD, b"1234");
        d.extend(tlv(TAG_NEW_PASSWORD, b"abcd"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
        assert_eq!(sw, Sw::OK);

        // Three failures exhaust the retry counter; then even the right PIN
        // fails, but CHANGE PIN still works.
        for _ in 0..3 {
            let (sw, _) = run(
                &mut app,
                &mut fs,
                &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"nope")),
            );
            assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"abcd")),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        let mut d = tlv(TAG_PASSWORD, b"abcd");
        d.extend(tlv(TAG_NEW_PASSWORD, b"1234"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
        assert_eq!(sw, Sw::OK);
        // The counter was restored by CHANGE PIN, so VERIFY works again.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn verify_code_checks_hotp_slot0() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // Slot 0 = HOTP credential at counter 0 → code 755224.
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None),
        );

        let mut d = tlv(TAG_NAME, b"h");
        d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
        assert_eq!(sw, Sw::OK);
        assert!(body.is_empty());
        // VERIFY CODE does not advance the counter.
        let mut d = tlv(TAG_NAME, b"h");
        d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
        assert_eq!(sw, Sw::OK);

        let mut d = tlv(TAG_NAME, b"h");
        d.extend(tlv(TAG_RESPONSE, &111111u32.to_be_bytes()));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
        assert_eq!(sw, SW_WRONG_DATA);
    }

    #[test]
    fn get_credential_returns_pws_fields() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let mut d = put_data(b"site", 0x21, 6, SECRET_SHA1, true, None);
        d.extend(tlv(TAG_PWS_LOGIN, b"user"));
        d.extend(tlv(TAG_PWS_PASSWORD, b"hunter2"));
        d.extend(tlv(TAG_PWS_METADATA, b"meta"));
        assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);

        let (sw, body) = run(
            &mut app,
            &mut fs,
            &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"site")),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&body, TAG_NAME as u16), Some(&b"site"[..]));
        assert_eq!(find_tag(&body, TAG_PWS_LOGIN as u16), Some(&b"user"[..]));
        assert_eq!(
            find_tag(&body, TAG_PWS_PASSWORD as u16),
            Some(&b"hunter2"[..])
        );
        assert_eq!(find_tag(&body, TAG_PWS_METADATA as u16), Some(&b"meta"[..]));
        assert_eq!(
            find_tag(&body, TAG_PROPERTY as u16),
            Some(&[PROP_TOUCH][..])
        );

        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"nope")),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
    }

    #[test]
    fn calculate_all_mixes_response_kinds() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        put(
            &mut app,
            &mut fs,
            &put_data(b"totp", 0x21, 8, SECRET_SHA1, false, None),
        );
        put(
            &mut app,
            &mut fs,
            &put_data(b"hotp", 0x11, 6, SECRET_SHA1, false, None),
        );
        put(
            &mut app,
            &mut fs,
            &put_data(b"tuch", 0x21, 7, SECRET_SHA1, true, None),
        );

        let chal = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
        assert_eq!(sw, Sw::OK);

        // Entry 1: full truncated TOTP response (RFC 6238 SHA-1 @ T=1).
        let mut expect = tlv(TAG_NAME, b"totp");
        let h = hmac_sha1(SECRET_SHA1, &1u64.to_be_bytes());
        let off = (h[19] & 0xF) as usize;
        expect.extend([TAG_RESPONSE + 1, 5, 8, h[off] & 0x7F]);
        expect.extend(&h[off + 1..off + 4]);
        // Entry 2: HOTP is not calculated in bulk.
        expect.extend(tlv(TAG_NAME, b"hotp"));
        expect.extend([TAG_NO_RESPONSE, 1, 6]);
        // Entry 3: touch-gated TOTP defers to individual CALCULATE.
        expect.extend(tlv(TAG_NAME, b"tuch"));
        expect.extend([TAG_TOUCH_RESPONSE, 1, 7]);
        assert_eq!(body, expect);

        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x02, &chal));
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &[]));
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
    }

    #[test]
    fn calculate_rejects_unknowns() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        // Unknown credential name.
        let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        d.extend(tlv(TAG_NAME, b"ghost"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
        assert_eq!(sw, Sw::DATA_INVALID);
        // Missing challenge.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_CALCULATE, 0, 1, &tlv(TAG_NAME, b"x")),
        );
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
        // Unknown algorithm nibble in a stored key fails cleanly.
        put(
            &mut app,
            &mut fs,
            &put_data(b"bad", 0x29, 6, SECRET_SHA1, false, None),
        );
        let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
        d.extend(tlv(TAG_NAME, b"bad"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
        assert_eq!(sw, Sw::EXEC_ERROR);
        // Bad CLA and unknown INS.
        let (sw, _) = run(&mut app, &mut fs, &[0x80, INS_LIST, 0, 0]);
        assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
        let (sw, _) = run(&mut app, &mut fs, &[0x00, 0xEE, 0, 0]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    }

    #[test]
    fn slots_fill_and_report_full() {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        for i in 0..MAX_OATH_CRED {
            let name = [b'n', (i >> 8) as u8, i as u8];
            assert_eq!(
                put(
                    &mut app,
                    &mut fs,
                    &put_data(&name, 0x21, 6, b"k0123456789abcdef", false, None)
                ),
                Sw::OK,
                "slot {i}"
            );
        }
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(b"overflow", 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::FILE_FULL
        );
    }
}
