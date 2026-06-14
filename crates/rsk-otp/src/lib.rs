// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico OTP applet — the YubiKey slot protocol over CCID: slot configure /
//! update / swap / delete, status, GET SERIAL / GET CONFIG, and HMAC-SHA1 /
//! Yubico-mode challenge-response. [`ticket`] and [`hid`] serve the keyboard side.

#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;

use rsk_crypto::{aes128_encrypt_block, ct_eq, hmac_sha1};
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

pub mod hid;
pub mod ticket;

#[cfg(test)]
mod tests_support;

/// OTP applet AID.
pub const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

/// Version reported in the status record — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`].
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Outcome of a touch request (CHAL_BTN_TRIG slots).
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

// FIDs: four contiguous slots — 1/2 (the classic short/long press) plus 3/4
// (0xBB02/0xBB03), addressed everywhere as `EF_OTP_SLOT1 + (slot - 1)`. Slots 3/4
// are reached over CCID via the P2 slot offset and typed by three/four BOOTSEL clicks.
pub(crate) const EF_OTP_SLOT1: u16 = 0xBB00;
const EF_OTP_SLOT2: u16 = 0xBB01;

/// Slot-config field offsets (packed, 52 bytes).
pub(crate) const FIXED_SIZE: usize = 16;
pub(crate) const UID_SIZE: usize = 6;
pub(crate) const KEY_SIZE: usize = 16;
const ACC_CODE_SIZE: usize = 6;
pub(crate) const OFF_UID: usize = FIXED_SIZE;
pub(crate) const OFF_AES_KEY: usize = OFF_UID + UID_SIZE;
const OFF_ACC_CODE: usize = OFF_AES_KEY + KEY_SIZE;
const OFF_FIXED_SIZE: usize = OFF_ACC_CODE + ACC_CODE_SIZE;
const OFF_EXT_FLAGS: usize = OFF_FIXED_SIZE + 1;
pub(crate) const OFF_TKT_FLAGS: usize = OFF_EXT_FLAGS + 1;
pub(crate) const OFF_CFG_FLAGS: usize = OFF_TKT_FLAGS + 1;
const OFF_RFU: usize = OFF_CFG_FLAGS + 1;
pub(crate) const CONFIG_SIZE: usize = OFF_RFU + 2 + 2; // rfu[2] + crc16 = 52

/// Slot files carry the 52-byte config plus an 8-byte counter tail (the dynamic
/// use counter for typed Yubico-OTP / the 64-bit HOTP moving factor).
pub(crate) const SLOT_SIZE: usize = CONFIG_SIZE + 8;

// Status `opts` bits.
const CONFIG1_VALID: u8 = 0x01;
const CONFIG2_VALID: u8 = 0x02;
const CONFIG1_TOUCH: u8 = 0x04;
const CONFIG2_TOUCH: u8 = 0x08;

// EXT flags.
const EXTFLAG_UPDATE_MASK: u8 = 0xFF; // SERIAL_* | USE_NUMERIC | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV

// TKT flags.
pub(crate) const TKT_OATH_HOTP: u8 = 0x40;
const TKT_CHAL_RESP: u8 = 0x40;
/// Append a carriage return after the typed ticket (`APPEND_CR`).
pub(crate) const TKT_APPEND_CR: u8 = 0x20;
const TKTFLAG_UPDATE_MASK: u8 = 0x3F; // TAB/DELAY/CR bits

// CFG flags.
pub(crate) const CFG_SHORT_TICKET: u8 = 0x02;
const CFG_HMAC_LT64: u8 = 0x04;
const CFG_CHAL_BTN_TRIG: u8 = 0x08;
pub(crate) const CFG_STATIC_TICKET: u8 = 0x20;
const CFG_CHAL_YUBICO: u8 = 0x20;
const CFG_CHAL_HMAC: u8 = 0x22;
/// Generate 8-digit HOTP rather than 6 (`OATH_HOTP8`).
pub(crate) const CFG_OATH_HOTP8: u8 = 0x02;
const CFGFLAG_UPDATE_MASK: u8 = 0x0C; // PACING_10MS | PACING_20MS

const INS_OTP: u8 = 0x01;

/// "Wrong data" in this protocol is reported as `0x6700` (wrong length).
const SW_WRONG_DATA: Sw = Sw::WRONG_LENGTH;

pub struct OtpApplet<'a> {
    serial_id: [u8; 8],
    presence: &'a RefCell<dyn UserPresence>,
    /// Status-record sequence number; bumped on every config write, reset on
    /// SELECT to 1/0 depending on whether any slot is programmed.
    config_seq: u8,
    /// Per-slot RAM session-use counter mixed into a typed Yubico-OTP token;
    /// resets each power cycle. One entry per slot (1–4).
    session_counter: [u8; 4],
}

impl<'a> OtpApplet<'a> {
    pub fn new(serial_id: [u8; 8], presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self {
            serial_id,
            presence,
            config_seq: 1,
            session_counter: [0; 4],
        }
    }

    /// Generate the typed ticket for a physical button press on `slot` (1–4: one
    /// or two clicks for the classic slots, three or four for slots 3/4). Builds
    /// the ticket via [`ticket::build`], persists any bumped use counter and
    /// writes the bytes to type into `out`. Returns `None` for an empty or
    /// challenge-response slot (nothing is typed). The `bool` is `true` when the
    /// bytes are ASCII to be keycode-mapped, `false` for raw scancodes.
    pub fn button_ticket<S: Storage>(
        &mut self,
        slot: u8,
        ts_secs: u32,
        rnd: [u8; 2],
        fs: &mut Fs<S>,
        out: &mut [u8; ticket::MAX_TICKET],
    ) -> Option<(usize, bool)> {
        if !(1..=4).contains(&slot) {
            return None;
        }
        let fid = EF_OTP_SLOT1 + (slot as u16 - 1);
        let mut buf = [0u8; SLOT_SIZE];
        let n = read_slot(fs, fid, &mut buf)?;
        if n < SLOT_SIZE {
            buf[CONFIG_SIZE..].fill(0);
        }
        // A Yubico challenge-response slot types nothing on a press.
        let tkt = buf[OFF_TKT_FLAGS];
        let cfg = buf[OFF_CFG_FLAGS];
        if cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0 {
            return None;
        }
        let idx = (slot - 1) as usize;
        let t = ticket::build(&buf, self.session_counter[idx], ts_secs, rnd, out)?;
        self.session_counter[idx] = t.new_session;
        if let Some(tail) = t.new_tail {
            let mut rec = buf;
            rec[CONFIG_SIZE..].copy_from_slice(&tail);
            let _ = fs.put(fid, &rec);
        }
        Some((t.len, t.encode))
    }

    /// First 10 chars of the serial hex string — mixed into the Yubico-mode
    /// challenge block.
    fn serial_str10(&self) -> [u8; 10] {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = [0u8; 10];
        for i in 0..5 {
            out[2 * i] = HEX[(self.serial_id[i] >> 4) as usize];
            out[2 * i + 1] = HEX[(self.serial_id[i] & 0xF) as usize];
        }
        out
    }

    /// The 7-byte status record body — version, sequence, valid/touch bits, a
    /// zero pad and the (idle) status byte. Shared by the CCID status response
    /// and the keyboard interface's status frame ([`Self::hid_status_frame`]).
    fn status_bytes<S: Storage>(&mut self, fs: &mut Fs<S>) -> [u8; 7] {
        let (maj, min, patch) = VERSION;
        let mut opts = 0u8;
        let mut slot = [0u8; SLOT_SIZE];
        if read_slot(fs, EF_OTP_SLOT1, &mut slot).is_some() {
            opts |= CONFIG1_VALID;
            if slot[OFF_TKT_FLAGS] & TKT_CHAL_RESP == 0
                || slot[OFF_CFG_FLAGS] & CFG_CHAL_BTN_TRIG != 0
            {
                opts |= CONFIG1_TOUCH;
            }
        }
        if read_slot(fs, EF_OTP_SLOT2, &mut slot).is_some() {
            opts |= CONFIG2_VALID;
            if slot[OFF_TKT_FLAGS] & TKT_CHAL_RESP == 0
                || slot[OFF_CFG_FLAGS] & CFG_CHAL_BTN_TRIG != 0
            {
                opts |= CONFIG2_TOUCH;
            }
        }
        // [maj, min, patch, config_seq, opts, pad, status_byte]; status_byte is
        // always idle here — the touch wait is signalled to the host through the
        // keyboard frame protocol's keepalive (see firmware `otp_kbd`).
        [maj, min, patch, self.config_seq, opts, 0, 0]
    }

    /// Push the 7-byte status record onto the CCID response.
    fn status<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        res.extend(&self.status_bytes(fs));
        Sw::OK
    }

    /// The 8-byte status frame returned by a keyboard-interface GET_REPORT poll:
    /// a leading reserved byte then the status record, so the host reads version
    /// at `[1..4]`, the program sequence at `[4]` and the slot valid/touch bits
    /// at `[5]`.
    pub fn hid_status_frame<S: Storage>(&mut self, fs: &mut Fs<S>) -> [u8; 8] {
        let b = self.status_bytes(fs);
        [0, b[0], b[1], b[2], b[3], b[4], b[5], b[6]]
    }

    /// Run one keyboard-interface frame command: the 64-byte payload becomes the
    /// APDU data and `slot_id` its P1. The response body (CRC framing is the
    /// transport's job) lands in `res`; an empty body means the host should read
    /// the status frame instead (a configure/swap that only bumps the seq).
    pub fn process_hid<S: Storage>(
        &mut self,
        slot_id: u8,
        payload: &[u8; 64],
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        let mut raw = [0u8; 5 + 64];
        raw[..5].copy_from_slice(&[0x00, INS_OTP, slot_id, 0x00, 64]);
        raw[5..].copy_from_slice(payload);
        match Apdu::parse(&raw) {
            Ok(apdu) => self.process(&apdu, fs, res),
            Err(_) => Sw::WRONG_LENGTH,
        }
    }

    /// P1 = 0x01/0x03: write or delete a slot config.
    fn cmd_configure<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p1 == 0x03 && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == 0x01 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        if apdu.nc < CONFIG_SIZE {
            return Sw::WRONG_LENGTH;
        }
        let data = &apdu.data[..apdu.nc];
        let mut stored = [0u8; SLOT_SIZE];
        if read_slot(fs, fid, &mut stored).is_some() {
            // Existing config: the host must present its access code.
            if data.len() < CONFIG_SIZE + ACC_CODE_SIZE {
                return Sw::WRONG_LENGTH;
            }
            if !ct_eq(
                &data[CONFIG_SIZE..CONFIG_SIZE + ACC_CODE_SIZE],
                &stored[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE],
            ) {
                return Sw::SECURITY_STATUS_NOT_SATISFIED;
            }
        }
        if data[..CONFIG_SIZE].iter().any(|&b| b != 0) {
            if data[OFF_RFU] != 0 || data[OFF_RFU + 1] != 0 || !check_crc(&data[..CONFIG_SIZE]) {
                return SW_WRONG_DATA;
            }
            let mut rec = [0u8; SLOT_SIZE];
            rec[..CONFIG_SIZE].copy_from_slice(&data[..CONFIG_SIZE]);
            if fs.put(fid, &rec).is_err() {
                return Sw::MEMORY_FAILURE;
            }
        } else {
            // An all-zero config deletes the slot.
            let _ = fs.delete(fid);
        }
        self.config_seq = self.config_seq.wrapping_add(1);
        self.status(fs, res)
    }

    /// P1 = 0x04/0x05: update the flag bytes of an existing config, keeping its
    /// fixed part / UID / key.
    fn cmd_update<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p1 == 0x05 && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == 0x04 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        if apdu.nc < CONFIG_SIZE {
            return Sw::WRONG_LENGTH;
        }
        let data = &apdu.data[..apdu.nc];
        if data[OFF_RFU] != 0 || data[OFF_RFU + 1] != 0 || !check_crc(&data[..CONFIG_SIZE]) {
            return SW_WRONG_DATA;
        }
        let mut stored = [0u8; SLOT_SIZE];
        if read_slot(fs, fid, &mut stored).is_some() {
            if data.len() < CONFIG_SIZE + ACC_CODE_SIZE {
                return Sw::WRONG_LENGTH;
            }
            if !ct_eq(
                &data[CONFIG_SIZE..CONFIG_SIZE + ACC_CODE_SIZE],
                &stored[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE],
            ) {
                return Sw::SECURITY_STATUS_NOT_SATISFIED;
            }
            let mut merged = [0u8; CONFIG_SIZE];
            merged.copy_from_slice(&data[..CONFIG_SIZE]);
            // Keep the secret material and fixed part; merge only the
            // updateable flag bits.
            merged[..OFF_ACC_CODE].copy_from_slice(&stored[..OFF_ACC_CODE]);
            merged[OFF_FIXED_SIZE] = stored[OFF_FIXED_SIZE];
            merged[OFF_EXT_FLAGS] = (stored[OFF_EXT_FLAGS] & !EXTFLAG_UPDATE_MASK)
                | (data[OFF_EXT_FLAGS] & EXTFLAG_UPDATE_MASK);
            merged[OFF_TKT_FLAGS] = (stored[OFF_TKT_FLAGS] & !TKTFLAG_UPDATE_MASK)
                | (data[OFF_TKT_FLAGS] & TKTFLAG_UPDATE_MASK);
            merged[OFF_CFG_FLAGS] = if stored[OFF_TKT_FLAGS] & TKT_CHAL_RESP == 0 {
                (stored[OFF_CFG_FLAGS] & !CFGFLAG_UPDATE_MASK)
                    | (data[OFF_CFG_FLAGS] & CFGFLAG_UPDATE_MASK)
            } else {
                stored[OFF_CFG_FLAGS]
            };
            if fs.put(fid, &merged).is_err() {
                return Sw::MEMORY_FAILURE;
            }
            self.config_seq = self.config_seq.wrapping_add(1);
        }
        self.status(fs, res)
    }

    /// P1 = 0x06: swap the two slots; the optional 2-byte body selects other
    /// slot pairs in the 4-slot layout.
    fn cmd_swap<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (mut fid1, mut fid2) = (EF_OTP_SLOT1, EF_OTP_SLOT2);
        if apdu.nc > 0 {
            if apdu.nc != 2 {
                return Sw::WRONG_LENGTH;
            }
            fid1 += apdu.data[0] as u16;
            fid2 += apdu.data[1] as u16;
        }
        let mut a = [0u8; SLOT_SIZE];
        let mut b = [0u8; SLOT_SIZE];
        let na = read_slot(fs, fid1, &mut a);
        let nb = read_slot(fs, fid2, &mut b);
        match nb {
            Some(n) => {
                if fs.put(fid1, &b[..n]).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
            }
            None => {
                let _ = fs.delete(fid1);
            }
        }
        match na {
            Some(n) => {
                if fs.put(fid2, &a[..n]).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
            }
            None => {
                let _ = fs.delete(fid2);
            }
        }
        self.config_seq = self.config_seq.wrapping_add(1);
        self.status(fs, res)
    }

    /// P1 = 0x14: per-slot flag/fixed-part TLVs (extended status).
    fn cmd_status_ext<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let mut slot = [0u8; SLOT_SIZE];
        for i in 0..4u16 {
            if read_slot(fs, EF_OTP_SLOT1 + i, &mut slot).is_none() {
                continue;
            }
            let tkt = slot[OFF_TKT_FLAGS];
            let cfg = slot[OFF_CFG_FLAGS];
            // A plain (typed) Yubico-OTP slot also reports its public id.
            let plain_otp = !(cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0)
                && tkt & TKT_OATH_HOTP == 0
                && cfg & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) == 0;
            res.push(0xB0 + i as u8);
            res.push(if plain_otp { 4 + 8 } else { 4 });
            res.push(0xA0);
            res.push(2);
            res.push(tkt);
            res.push(cfg);
            if plain_otp {
                res.push(0xC0);
                res.push(6);
                res.extend(&slot[..6]);
            }
        }
        Sw::OK
    }

    /// P1 = 0x20/0x28 (Yubico mode) / 0x30/0x38 (HMAC-SHA1): challenge-response.
    /// Challenge lengths are required up front — never overread the body.
    fn cmd_calculate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if (apdu.p1 == 0x38 || apdu.p1 == 0x28) && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == 0x30 || apdu.p1 == 0x20 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        let mut slot = [0u8; SLOT_SIZE];
        if read_slot(fs, fid, &mut slot).is_none() {
            // Protocol quirk: an empty slot answers 9000 with no body.
            return Sw::OK;
        }
        let tkt = slot[OFF_TKT_FLAGS];
        let cfg = slot[OFF_CFG_FLAGS];
        if tkt & TKT_CHAL_RESP == 0 {
            return SW_WRONG_DATA;
        }
        if cfg & CFG_CHAL_BTN_TRIG != 0
            && self.presence.borrow_mut().request() != Presence::Confirmed
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if apdu.p1 == 0x30 || apdu.p1 == 0x38 {
            if cfg & CFG_CHAL_HMAC == 0 {
                return SW_WRONG_DATA;
            }
            if data.len() < 64 {
                return Sw::WRONG_LENGTH;
            }
            // HMAC key = AES field + all 6 UID bytes (22 total). HMAC zero-pads
            // keys, so with the zero UID tail this equals the 20-byte-key HMAC.
            let mut key = [0u8; KEY_SIZE + UID_SIZE];
            key[..KEY_SIZE].copy_from_slice(&slot[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
            key[KEY_SIZE..].copy_from_slice(&slot[OFF_UID..OFF_UID + UID_SIZE]);
            // Variable-length challenges are padded by repeating the final
            // byte; trim that padding back off.
            let mut chal_len = 64usize;
            if cfg & CFG_HMAC_LT64 != 0 {
                while chal_len > 0 && data[chal_len - 1] == data[63] {
                    chal_len -= 1;
                }
            }
            res.extend(&hmac_sha1(&key, &data[..chal_len]));
        } else {
            if cfg & CFG_CHAL_YUBICO == 0 {
                return SW_WRONG_DATA;
            }
            if data.len() < 6 {
                return Sw::WRONG_LENGTH;
            }
            // Challenge block = 6 host bytes + 10 chars of the serial string.
            let mut block = [0u8; 16];
            block[..6].copy_from_slice(&data[..6]);
            block[6..].copy_from_slice(&self.serial_str10());
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&slot[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
            aes128_encrypt_block(&key, &mut block);
            res.extend(&block);
        }
        Sw::OK
    }

    fn cmd_otp<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.p1 {
            0x01 | 0x03 => self.cmd_configure(apdu, fs, res),
            0x04 | 0x05 => self.cmd_update(apdu, fs, res),
            0x06 => self.cmd_swap(apdu, fs, res),
            0x10 => {
                res.extend(&rsk_mgmt::serial4(self.serial_id));
                Sw::OK
            }
            0x13 => rsk_mgmt::config_tlv(&rsk_mgmt::serial4(self.serial_id), fs, res),
            0x14 => self.cmd_status_ext(fs, res),
            0x20 | 0x28 | 0x30 | 0x38 => self.cmd_calculate(apdu, fs, res),
            // Unknown P1 values fall through to a bare OK.
            _ => Sw::OK,
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for OtpApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        OTP_AID
    }

    /// SELECT returns the status record.
    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        self.config_seq = u8::from(fs.has_data(EF_OTP_SLOT1) || fs.has_data(EF_OTP_SLOT2));
        self.status(fs, res)
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_OTP => self.cmd_otp(apdu, fs, res),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Read a slot file; `Some(len)` only when it holds at least a full config.
pub(crate) fn read_slot<S: Storage>(
    fs: &mut Fs<S>,
    fid: u16,
    buf: &mut [u8; SLOT_SIZE],
) -> Option<usize> {
    let n = fs.read(fid, buf)?.min(SLOT_SIZE);
    (n >= CONFIG_SIZE).then_some(n)
}

/// Boot-time use-counter bump: on power-up, advance the 16-bit use counter of
/// every plain Yubico-OTP slot (skipping HOTP / short / static slots), so a
/// counter never repeats across reboots — the YubiKey replay defence. Runs once
/// at startup.
pub fn power_up_bump<S: Storage>(fs: &mut Fs<S>) {
    let mut slot = [0u8; SLOT_SIZE];
    for i in 0..4u16 {
        let fid = EF_OTP_SLOT1 + i;
        let Some(n) = read_slot(fs, fid, &mut slot) else {
            continue;
        };
        let tkt = slot[OFF_TKT_FLAGS];
        let cfg = slot[OFF_CFG_FLAGS];
        if tkt & TKT_OATH_HOTP != 0 || cfg & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) != 0 {
            continue;
        }
        // The counter lives in the first two tail bytes (big-endian).
        let mut rec = slot;
        if n < SLOT_SIZE {
            rec[CONFIG_SIZE..].fill(0);
        }
        let counter = u16::from_be_bytes([rec[CONFIG_SIZE], rec[CONFIG_SIZE + 1]]).wrapping_add(1);
        if counter <= 0x7FFF {
            rec[CONFIG_SIZE..CONFIG_SIZE + 2].copy_from_slice(&counter.to_be_bytes());
            let _ = fs.put(fid, &rec);
        }
    }
}

/// CRC16 X.25 / CRC-CCITT reflected, poly 0x8408.
pub(crate) fn crc16(data: &[u8]) -> u16 {
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

/// A valid config CRCs (over all 52 bytes, the stored ~CRC included) to the
/// X.25 residual.
fn check_crc(config: &[u8]) -> bool {
    crc16(config) == 0xF0B8
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    const SERIAL: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0, 0, 0];
    /// Typed-ticket flag used to build non-chalresp test slots.
    const TKT_APPEND_CR: u8 = 0x20;

    /// Presence stub the tests can flip to Declined.
    struct TestPresence(Presence);
    impl UserPresence for TestPresence {
        fn request(&mut self) -> Presence {
            self.0
        }
    }

    fn new_fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    fn select(app: &mut OtpApplet, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::select(app, false, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    fn run(app: &mut OtpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 1024];
        let mut res = ResBuf::new(&mut out);
        let apdu = Apdu::parse(raw).unwrap();
        let sw = Applet::process(app, &apdu, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    fn otp_apdu(p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 256);
        let mut v = vec![0x00, INS_OTP, p1, p2];
        if !data.is_empty() {
            v.push(data.len() as u8);
            v.extend_from_slice(data);
        }
        v
    }

    /// Build a valid 52-byte config the way ykman does: fill the fields, then
    /// store the complement of the CRC over the first 50 bytes.
    fn build_config(
        fixed: &[u8],
        uid: &[u8; 6],
        key: &[u8; 16],
        acc: &[u8; 6],
        ext: u8,
        tkt: u8,
        cfg: u8,
    ) -> [u8; CONFIG_SIZE] {
        let mut c = [0u8; CONFIG_SIZE];
        c[..fixed.len()].copy_from_slice(fixed);
        c[OFF_UID..OFF_UID + 6].copy_from_slice(uid);
        c[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(key);
        c[OFF_ACC_CODE..OFF_ACC_CODE + 6].copy_from_slice(acc);
        c[OFF_FIXED_SIZE] = fixed.len() as u8;
        c[OFF_EXT_FLAGS] = ext;
        c[OFF_TKT_FLAGS] = tkt;
        c[OFF_CFG_FLAGS] = cfg;
        let crc = !crc16(&c[..CONFIG_SIZE - 2]);
        c[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
        c
    }

    /// HMAC-SHA1 challenge-response config (the `ykman otp chalresp` layout):
    /// 16 key bytes in the AES field, 4 in the UID head.
    fn chalresp_config(key20: &[u8; 20], acc: &[u8; 6], cfg_extra: u8) -> [u8; CONFIG_SIZE] {
        let mut uid = [0u8; 6];
        uid[..4].copy_from_slice(&key20[16..]);
        let mut aes = [0u8; 16];
        aes.copy_from_slice(&key20[..16]);
        build_config(
            &[],
            &uid,
            &aes,
            acc,
            0,
            TKT_CHAL_RESP,
            CFG_CHAL_HMAC | cfg_extra,
        )
    }

    fn configure(
        app: &mut OtpApplet,
        fs: &mut Fs<RamStorage>,
        p1: u8,
        p2: u8,
        config: &[u8; CONFIG_SIZE],
        acc: &[u8; 6],
    ) -> (Sw, Vec<u8>) {
        let mut d = config.to_vec();
        d.extend_from_slice(acc);
        run(app, fs, &otp_apdu(p1, p2, &d))
    }

    #[test]
    fn crc16_residual() {
        // Programming-frame self-check: a stored ~CRC makes the whole-record
        // CRC equal the X.25 residual.
        let c = build_config(b"fix", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
        assert!(check_crc(&c));
        let mut bad = c;
        bad[0] ^= 1;
        assert!(!check_crc(&bad));
    }

    #[test]
    fn button_types_nitrokey_slots_3_and_4() {
        // Slots 3/4 (three/four BOOTSEL clicks) type a ticket just like 1/2:
        // configure over CCID with the P2 slot offset (P1=0x01, P2=2/3 →
        // EF 0xBB02/0xBB03); a fifth slot is rejected.
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        // Plain Yubico-OTP slot (tkt = cfg = 0): types a 44-char modhex + bumps the
        // use counter, so this also covers per-slot counter persistence on slot 3/4.
        let cfg = build_config(&[0, 1, 2, 3, 4, 5], &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
        assert_eq!(
            configure(&mut app, &mut fs, 0x01, 2, &cfg, &[0; 6]).0,
            Sw::OK
        );
        assert_eq!(
            configure(&mut app, &mut fs, 0x01, 3, &cfg, &[0; 6]).0,
            Sw::OK
        );

        let mut out = [0u8; ticket::MAX_TICKET];
        assert!(app.button_ticket(3, 0, [0, 0], &mut fs, &mut out).is_some());
        assert!(app.button_ticket(4, 0, [0, 0], &mut fs, &mut out).is_some());
        // Out of range — there is no fifth slot.
        assert!(app.button_ticket(5, 0, [0, 0], &mut fs, &mut out).is_none());
        // And a 0x14 extended status now lists all four programmed slots.
        let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x14, 0, &[]));
        assert_eq!(
            body.iter().filter(|&&b| (0xB0..0xB4).contains(&b)).count(),
            2
        );
    }

    #[test]
    fn select_status_and_config_seq() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let (sw, body) = select(&mut app, &mut fs);
        assert_eq!(sw, Sw::OK);
        // Empty device: version 5.7.4, seq 0, no valid/touch bits.
        assert_eq!(body, [5, 7, 4, 0, 0, 0, 0]);

        // Program slot 1 (HMAC chalresp, no touch): VALID without TOUCH.
        let cfgd = chalresp_config(&[0xAA; 20], &[0; 6], 0);
        let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&body[..4], &[5, 7, 4, 1]); // seq bumped
        assert_eq!(body[4], CONFIG1_VALID);

        // Re-SELECT: seq resets to 1 (slots present).
        let (_, body) = select(&mut app, &mut fs);
        assert_eq!(body[3], 1);

        // A typed (non-chalresp) slot 2 sets VALID + TOUCH.
        let typed = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
        let (_, body) = configure(&mut app, &mut fs, 0x03, 0, &typed, &[0; 6]);
        assert_eq!(body[4], CONFIG1_VALID | CONFIG2_VALID | CONFIG2_TOUCH);
    }

    #[test]
    fn configure_validates_crc_and_rfu() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let mut bad = chalresp_config(&[1; 20], &[0; 6], 0);
        bad[10] ^= 0xFF; // breaks the CRC
        let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &bad, &[0; 6]);
        assert_eq!(sw, SW_WRONG_DATA);

        let mut bad = chalresp_config(&[1; 20], &[0; 6], 0);
        bad[OFF_RFU] = 1; // rfu must be zero (CRC recomputed to stay valid)
        let crc = !crc16(&bad[..CONFIG_SIZE - 2]);
        bad[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
        let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &bad, &[0; 6]);
        assert_eq!(sw, SW_WRONG_DATA);

        // Too-short body.
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x01, 0, &[0u8; 20]));
        assert_eq!(sw, Sw::WRONG_LENGTH);
        // Slot-2 configure with nonzero P2 is invalid.
        let good = chalresp_config(&[1; 20], &[0; 6], 0);
        let (sw, _) = configure(&mut app, &mut fs, 0x03, 1, &good, &[0; 6]);
        assert_eq!(sw, Sw::INCORRECT_P1P2);
    }

    #[test]
    fn access_code_protects_reconfig_and_delete() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let acc = [1, 2, 3, 4, 5, 6];
        let cfgd = chalresp_config(&[0xBB; 20], &acc, 0);
        let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
        assert_eq!(sw, Sw::OK);

        // Overwrite without the access code fails…
        let newc = chalresp_config(&[0xCC; 20], &[0; 6], 0);
        let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &newc, &[0; 6]);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        // …and succeeds with it.
        let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &newc, &acc);
        assert_eq!(sw, Sw::OK);

        // Delete = all-zero config (plus the current access code — now none).
        let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &[0; CONFIG_SIZE], &[0; 6]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[4], 0); // no valid slots
    }

    #[test]
    fn hmac_chalresp_full_64() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let key20 = [0x0B; 20];
        let cfgd = chalresp_config(&key20, &[0; 6], 0); // no HMAC_LT64: full 64 bytes
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

        let chal = [0x5A; 64];
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
        assert_eq!(sw, Sw::OK);
        // Key = AES field (16) + full UID (6); trailing UID zeros are absorbed
        // by HMAC key padding, so this equals the plain 20-byte-key HMAC.
        assert_eq!(body, hmac_sha1(&key20, &chal));
    }

    #[test]
    fn hmac_chalresp_lt64_trims_padding() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let key20 = [0x0B; 20];
        let cfgd = chalresp_config(&key20, &[0; 6], CFG_HMAC_LT64);
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

        // KeePassXC-style: short challenge padded by repeating the last byte.
        let mut chal = [0x01u8; 64];
        chal[..9].copy_from_slice(b"challenge");
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, hmac_sha1(&key20, b"challenge"));

        // The classic trim quirk: a challenge ending in the pad byte loses its
        // own tail ("Hi There" + 'e' padding → "Hi Ther").
        let mut chal = [b'e'; 64];
        chal[..8].copy_from_slice(b"Hi There");
        let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
        assert_eq!(body, hmac_sha1(&key20, b"Hi Ther"));
        // RFC 2202 case 1 pins the PRF itself for the trimmed message.
        assert_ne!(body, hmac_sha1(&key20, b"Hi There"));
    }

    #[test]
    fn yubico_chalresp_mixes_serial() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let aes_key = [0x42; 16];
        let cfgd = build_config(
            &[],
            &[0; 6],
            &aes_key,
            &[0; 6],
            0,
            TKT_CHAL_RESP,
            CFG_CHAL_YUBICO,
        );
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

        let chal6 = [9, 8, 7, 6, 5, 4];
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x20, 0, &chal6));
        assert_eq!(sw, Sw::OK);
        let mut expect = [0u8; 16];
        expect[..6].copy_from_slice(&chal6);
        expect[6..].copy_from_slice(b"123456789A"); // serial_str10 of SERIAL
        aes128_encrypt_block(&aes_key, &mut expect);
        assert_eq!(body, expect);
    }

    #[test]
    fn calculate_rejections_and_empty_slot() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        // Empty slot: bare OK, no body.
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
        assert_eq!((sw, body.len()), (Sw::OK, 0));

        // Non-chalresp slot rejects calculation.
        let typed = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
        configure(&mut app, &mut fs, 0x01, 0, &typed, &[0; 6]);
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
        assert_eq!(sw, SW_WRONG_DATA);

        // Short challenge bodies are length errors, not buffer overreads.
        let cfgd = chalresp_config(&[1; 20], &[0; 6], 0);
        configure(&mut app, &mut fs, 0x03, 0, &cfgd, &[0; 6]);
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &[0; 32]));
        assert_eq!(sw, Sw::WRONG_LENGTH);
        // Slot-2 variants demand P2 = 0.
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x38, 1, &[0; 64]));
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        // Unknown INS / CLA.
        let (sw, _) = run(&mut app, &mut fs, &[0x00, 0x02, 0, 0]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
        let (sw, _) = run(&mut app, &mut fs, &[0x80, 0x01, 0x10, 0]);
        assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
        // Unknown P1 answers a bare OK.
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x77, 0, &[]));
        assert_eq!((sw, body.len()), (Sw::OK, 0));
    }

    #[test]
    fn touch_gated_chalresp_respects_presence() {
        let mut fs = new_fs();
        let presence = RefCell::new(TestPresence(Presence::Declined));
        let presence_dyn: &RefCell<dyn UserPresence> = &presence;
        let mut app = OtpApplet::new(SERIAL, presence_dyn);
        let cfgd = chalresp_config(&[7; 20], &[0; 6], CFG_CHAL_BTN_TRIG);
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
        presence.borrow_mut().0 = Presence::Confirmed;
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body.len(), 20);
    }

    #[test]
    fn update_merges_flag_masks_only() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        // A typed Yubico-OTP slot (not chal-resp) with APPEND_CR.
        let orig = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
        configure(&mut app, &mut fs, 0x01, 0, &orig, &[0; 6]);

        // Update with different key material + flags: only the masked tkt/cfg
        // bits may change; the key/fixed/uid stay.
        let upd = build_config(
            b"other!", &[9; 6], &[9; 16], &[0; 6], 0, 0x02, /* APPEND_TAB1 */
            0xFF,
        );
        let mut d = upd.to_vec();
        d.extend_from_slice(&[0; 6]);
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &d));
        assert_eq!(sw, Sw::OK);

        // status-ext shows the merged flags and the ORIGINAL fixed part.
        let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x14, 0, &[]));
        // [0xB0, len, 0xA0, 2, tkt, cfg, 0xC0, 6, fixed6...]
        assert_eq!(body[0], 0xB0);
        assert_eq!(body[4], 0x02); // tkt: only the update-mask bit survived
        assert_eq!(body[5], 0x0C); // cfg: only PACING bits taken from 0xFF
        assert_eq!(&body[8..14], b"public");

        // Update on an empty slot stores nothing but still returns status.
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x05, 0, &d));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[4] & CONFIG2_VALID, 0);
    }

    #[test]
    fn swap_moves_configs_between_slots() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let key20 = [0x33; 20];
        let cfgd = chalresp_config(&key20, &[0; 6], 0);
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[4], CONFIG2_VALID); // moved 1 → 2

        // The moved slot still calculates (now via the slot-2 variant).
        let chal = [0x11; 64];
        let (_, resp) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &chal));
        assert_eq!(resp, hmac_sha1(&key20, &chal));

        // Swap back with an explicit pair body — the offsets are relative to
        // slot 1 resp. slot 2, so [0, 0] is the plain 1↔2 swap.
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 0]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[4], CONFIG1_VALID);
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 1, 2]));
        assert_eq!(sw, Sw::WRONG_LENGTH);
    }

    #[test]
    fn serial_and_config_passthrough() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x10, 0, &[]));
        assert_eq!(sw, Sw::OK);
        // serial4: first 4 chip-id bytes, top 6 bits cleared (0x12 → 0x02).
        assert_eq!(body, [0x02, 0x34, 0x56, 0x78]);

        // GET CONFIG returns the management TLV (leading overall-length byte).
        let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x13, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body[0] as usize, body.len() - 1);
    }

    /// The DeviceInfo read ykman falls back to when CCID is unavailable
    /// (`yubikit._ManagementOtpBackend.read_config` → slot 0x13), end to end
    /// over the frame protocol: host frame in via [`hid::FrameRx`], dispatch
    /// via `process_hid`, response out via [`hid::FrameTx`], validated exactly
    /// as the host does (length byte + X.25 CRC residual).
    #[test]
    fn hid_frame_device_info_read() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);

        // read_config(page=0) sends a single zero page byte (already zero).
        let payload = [0u8; hid::PAYLOAD_SIZE];
        let reports = hid::split_frame(&payload, 0x13);
        let mut rx = hid::FrameRx::new();
        let mut frame = None;
        for r in &reports {
            if let hid::RxOutcome::Frame { slot, payload } = rx.feed(r) {
                frame = Some((slot, payload));
            }
        }
        let (slot, payload) = frame.expect("frame did not reassemble");
        assert_eq!(slot, 0x13);

        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);
        let sw = app.process_hid(slot, &payload, &mut fs, &mut res);
        assert_eq!(sw, Sw::OK);
        let body = res.as_slice().to_vec();
        assert!(!body.is_empty(), "a read command must stream a body");

        // Drain the response reports the way `yubikit._read_frame` does.
        let mut tx = hid::FrameTx::new();
        tx.load(&body);
        let mut resp = Vec::new();
        let mut rep = [0u8; hid::REPORT_SIZE];
        let mut seq = 0u8;
        while tx.next(&mut rep) {
            let flag = rep[hid::REPORT_DATA];
            assert_ne!(flag & 0x40, 0, "response report must set RESP_PENDING");
            if flag & 0x1F == seq {
                resp.extend_from_slice(&rep[..hid::REPORT_DATA]);
                seq += 1;
            } else {
                assert_eq!(flag & 0x1F, 0, "sequence break that is not the end marker");
                break;
            }
        }
        // yubikit read_config: r_len = response[0]; check_crc(response[:r_len+3]).
        let r_len = resp[0] as usize;
        assert_eq!(r_len, body.len() - 1);
        assert_eq!(crc16(&resp[..r_len + 3]), 0xF0B8);
        assert_eq!(&resp[..r_len + 1], &body[..]);
    }

    /// Frame commands we do not implement (e.g. SLOT_YK4_SET_DEVICE_INFO 0x15)
    /// answer OK with no body — the firmware glue then serves the idle status
    /// frame, which yubikit turns into a clean CommandRejectedError("No data")
    /// instead of blocking in `_read_frame`.
    #[test]
    fn hid_frame_unknown_command_answers_empty() {
        let mut fs = new_fs();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OtpApplet::new(SERIAL, &presence);
        for slot in [0x11u8, 0x12, 0x15] {
            let payload = [0u8; hid::PAYLOAD_SIZE];
            let mut out = [0u8; 64];
            let mut res = ResBuf::new(&mut out);
            let sw = app.process_hid(slot, &payload, &mut fs, &mut res);
            assert_eq!(sw, Sw::OK);
            assert!(
                res.as_slice().is_empty(),
                "slot {slot:#x} must not stream a body"
            );
        }
    }
}
