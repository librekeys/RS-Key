// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico management applet: reports device capabilities, serial and firmware
//! version — what `ykman` / Yubico Authenticator SELECT first to identify the key.
//! READ CONFIG (0x1D) returns the DeviceInfo TLV; WRITE CONFIG (0x1C) persists it.
#![cfg_attr(not(test), no_std)]

use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Management applet AID.
pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Reported firmware version `(major, minor, patch)` — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] so CTAP getInfo, the DeviceInfo TLV and `ykman`
/// all agree.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

// Capability bits.
const CAP_OTP: u16 = 0x01;
const CAP_U2F: u16 = 0x02;
const CAP_OPENPGP: u16 = 0x08;
const CAP_OATH: u16 = 0x20;
const CAP_FIDO2: u16 = 0x200;
const CAP_PIV: u16 = 0x10;

/// Capabilities this firmware actually implements. Reporting only what exists
/// keeps Yubico Authenticator from showing tabs that would error on SELECT.
const SUPPORTED_CAPS: u16 = CAP_FIDO2 | CAP_U2F | CAP_OPENPGP | CAP_OATH | CAP_OTP | CAP_PIV;

// DeviceInfo TLV tags.
const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIG_LOCK: u8 = 0x0A;

const FLAG_EJECT: u8 = 0x80;
const FORM_FACTOR_USB_A_KEYCHAIN: u8 = 0x01;

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;
const INS_RESET: u8 = 0x1E;

/// EF holding the persisted enabled-applications TLV. Outside both the FIDO and
/// OpenPGP reset scopes, so the capability config is sticky.
const EF_DEV_CONF: u16 = 0x1122;

/// Bytes of `EF_DEV_CONF` that READ CONFIG can echo back — the size of the fixed
/// buffer it reads into. WRITE CONFIG refuses to persist more (a host config is
/// a handful of small TLVs), so a read can never slice past the buffer.
const EF_DEV_CONF_MAX: usize = 64;

pub struct ManagementApplet {
    /// First 4 bytes of the chip id → the 8-digit serial.
    serial: [u8; 4],
}

/// First 4 bytes of the chip id with the top 6 bits cleared (`&= ~0xFC`) — the
/// 8-digit Yubico serial. Shared with the OTP applet's GET SERIAL.
pub fn serial4(serial_id: [u8; 8]) -> [u8; 4] {
    let mut serial = [0u8; 4];
    serial.copy_from_slice(&serial_id[..4]);
    serial[0] &= 0x03;
    serial
}

/// Build the READ CONFIG TLV: a leading overall-length byte, then
/// USB_SUPPORTED / SERIAL / FORM_FACTOR / VERSION, then either the persisted
/// `EF_DEV_CONF` blob or the default USB_ENABLED / DEVICE_FLAGS / CONFIG_LOCK
/// tail. Public because the OTP applet serves the same TLV (P1=0x13).
pub fn config_tlv<S: Storage>(serial: &[u8; 4], fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
    let mut buf = [0u8; 128];
    let mut n = 1; // byte 0 = overall length, filled at the end.

    push_tlv(
        &mut buf,
        &mut n,
        TAG_USB_SUPPORTED,
        &SUPPORTED_CAPS.to_be_bytes(),
    );
    push_tlv(&mut buf, &mut n, TAG_SERIAL, serial);
    push_tlv(
        &mut buf,
        &mut n,
        TAG_FORM_FACTOR,
        &[FORM_FACTOR_USB_A_KEYCHAIN],
    );
    let (maj, min, patch) = VERSION;
    push_tlv(&mut buf, &mut n, TAG_VERSION, &[maj, min, patch]);

    let mut conf = [0u8; EF_DEV_CONF_MAX];
    match fs.read(EF_DEV_CONF, &mut conf) {
        Some(full) if full > 0 => {
            // A host wrote an enabled-applications config — return it verbatim.
            // `Storage::read` reports the value's *full* length even when it
            // exceeds the buffer, so clamp before slicing: WRITE CONFIG caps new
            // writes, but a blob persisted by an older build or a corrupt flash
            // could still be over-length and must not slice past `conf`/`buf`.
            let len = full.min(conf.len()).min(buf.len().saturating_sub(n));
            buf[n..n + len].copy_from_slice(&conf[..len]);
            n += len;
        }
        _ => {
            // Defaults: everything supported is enabled, removable, unlocked.
            push_tlv(
                &mut buf,
                &mut n,
                TAG_USB_ENABLED,
                &SUPPORTED_CAPS.to_be_bytes(),
            );
            push_tlv(&mut buf, &mut n, TAG_DEVICE_FLAGS, &[FLAG_EJECT]);
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[0x00]);
        }
    }

    buf[0] = (n - 1) as u8;
    res.extend(&buf[..n]);
    Sw::OK
}

impl ManagementApplet {
    /// `serial_id` is the device chip id; its first 4 bytes form the serial.
    pub fn new(serial_id: [u8; 8]) -> Self {
        Self {
            serial: serial4(serial_id),
        }
    }

    /// Serve READ CONFIG to a non-CCID transport — the same DeviceInfo TLV as the
    /// CCID path. The OTP keyboard interface and the CTAPHID Management vendor
    /// command both answer it (a YubiKey replies on every transport).
    pub fn read_config<S: Storage>(&self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        config_tlv(&self.serial, fs, res)
    }

    /// WRITE CONFIG: the first data byte is the length of the rest; persist that
    /// TLV blob as `EF_DEV_CONF`.
    fn write_config<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.nc == 0 || apdu.data[0] as usize != apdu.nc - 1 {
            return Sw::INCORRECT_PARAMS;
        }
        // READ CONFIG echoes this blob back through a fixed `EF_DEV_CONF_MAX`
        // buffer; refuse to persist more than fits so a read can never slice out
        // of bounds (an over-length blob would otherwise be a sticky DoS — it
        // lives in flash and crashes every DeviceInfo query until wiped).
        if apdu.nc - 1 > EF_DEV_CONF_MAX {
            return Sw::INCORRECT_PARAMS;
        }
        match fs.put(EF_DEV_CONF, &apdu.data[1..apdu.nc]) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for ManagementApplet {
    fn aid(&self) -> &'static [u8] {
        MANAGEMENT_AID
    }

    /// SELECT returns the firmware version as an ASCII string.
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        push_dec(res, maj);
        res.push(b'.');
        push_dec(res, min);
        res.push(b'.');
        push_dec(res, patch);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_READ_CONFIG => config_tlv(&self.serial, fs, res),
            INS_WRITE_CONFIG => self.write_config(apdu, fs),
            // Device-wide factory reset is not implemented; ykman resets FIDO
            // over CTAP instead.
            INS_RESET => Sw::INS_NOT_SUPPORTED,
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Append a `tag, len, value` TLV; silently truncated by the fixed `read_config`
/// buffer (sized for the largest config, so this never actually overflows).
fn push_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) {
    if *n + 2 + val.len() > buf.len() {
        return;
    }
    buf[*n] = tag;
    buf[*n + 1] = val.len() as u8;
    buf[*n + 2..*n + 2 + val.len()].copy_from_slice(val);
    *n += 2 + val.len();
}

/// Append a `u8` as 1-3 ASCII decimal digits.
fn push_dec(res: &mut ResBuf, v: u8) {
    if v >= 100 {
        res.push(b'0' + v / 100);
    }
    if v >= 10 {
        res.push(b'0' + (v / 10) % 10);
    }
    res.push(b'0' + v % 10);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::Fs;
    use rsk_fs::storage::ram::RamStorage;
    use rsk_sdk::Apdu;

    fn fs() -> Fs<RamStorage> {
        Fs::new(RamStorage::new(), &[])
    }

    fn select(app: &mut ManagementApplet, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::select(app, false, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    fn process(app: &mut ManagementApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let apdu = Apdu::parse(raw).unwrap();
        let sw = Applet::process(app, &apdu, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    /// Walk a TLV blob, returning the value for `tag`.
    fn tlv_get(blob: &[u8], tag: u8) -> Option<&[u8]> {
        let mut i = 0;
        while i + 2 <= blob.len() {
            let t = blob[i];
            let l = blob[i + 1] as usize;
            if i + 2 + l > blob.len() {
                return None;
            }
            if t == tag {
                return Some(&blob[i + 2..i + 2 + l]);
            }
            i += 2 + l;
        }
        None
    }

    #[test]
    fn select_returns_version_string() {
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        let (sw, body) = select(&mut app, &mut fs);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&body, b"5.7.4");
    }

    #[test]
    fn read_config_reports_version_caps_serial() {
        let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
        let mut fs = fs();
        let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        assert_eq!(sw, Sw::OK);
        // Leading overall-length byte.
        assert_eq!(body[0] as usize, body.len() - 1);
        let tlv = &body[1..];
        assert_eq!(tlv_get(tlv, TAG_VERSION), Some(&[5u8, 7, 4][..]));
        assert_eq!(
            tlv_get(tlv, TAG_USB_SUPPORTED),
            Some(&SUPPORTED_CAPS.to_be_bytes()[..])
        );
        // Serial MSB had its top 6 bits cleared (8-digit cap): 0x12 & 0x03 = 0x02.
        assert_eq!(
            tlv_get(tlv, TAG_SERIAL),
            Some(&[0x02, 0x34, 0x56, 0x78][..])
        );
        // Default tail present (no EF_DEV_CONF written yet).
        assert_eq!(
            tlv_get(tlv, TAG_USB_ENABLED),
            Some(&SUPPORTED_CAPS.to_be_bytes()[..])
        );
        assert_eq!(tlv_get(tlv, TAG_CONFIG_LOCK), Some(&[0x00][..]));
    }

    #[test]
    fn read_config_matches_ccid_read_config() {
        // `read_config` must be byte-identical to the CCID INS_READ_CONFIG
        // DeviceInfo so ykman sees the same key on every interface.
        let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
        let mut fs = fs();
        let (_, ccid) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        assert_eq!(app.read_config(&mut fs, &mut res), Sw::OK);
        assert_eq!(res.as_slice(), &ccid[..]);
    }

    #[test]
    fn write_then_read_config_roundtrips() {
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        // Enable only FIDO2 + U2F (TAG_USB_ENABLED = 0x0202).
        let blob = [TAG_USB_ENABLED, 0x02, 0x02, 0x02];
        let mut cmd = std::vec![
            0x00,
            INS_WRITE_CONFIG,
            0,
            0,
            (blob.len() + 1) as u8,
            blob.len() as u8
        ];
        cmd.extend_from_slice(&blob);
        let (sw, _) = process(&mut app, &mut fs, &cmd);
        assert_eq!(sw, Sw::OK);

        let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        assert_eq!(sw, Sw::OK);
        let tlv = &body[1..];
        // The stored blob is echoed verbatim after the fixed prefix.
        assert_eq!(tlv_get(tlv, TAG_USB_ENABLED), Some(&[0x02, 0x02][..]));
        // The default DEVICE_FLAGS/CONFIG_LOCK tail is gone (replaced by the blob).
        assert_eq!(tlv_get(tlv, TAG_CONFIG_LOCK), None);
    }

    #[test]
    fn write_config_rejects_oversized_blob() {
        // An inner blob larger than the read buffer must be refused, so it can
        // never become a sticky DoS that panics every later READ CONFIG.
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        let inner = EF_DEV_CONF_MAX + 1;
        let mut cmd = std::vec![
            0x00,
            INS_WRITE_CONFIG,
            0,
            0,
            (inner + 1) as u8, // Lc = leading length byte + inner
            inner as u8        // data[0] = inner (== nc - 1)
        ];
        cmd.extend_from_slice(&std::vec![0xAB; inner]);
        let (sw, _) = process(&mut app, &mut fs, &cmd);
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
        // Nothing was persisted.
        assert!(fs.read(EF_DEV_CONF, &mut [0u8; 8]).is_none());
    }

    #[test]
    fn read_config_survives_oversized_stored_blob() {
        // Regression: READ CONFIG used to slice `&conf[..len]` with `len` =
        // Storage::read's *full* stored length, so a >64-byte EF_DEV_CONF
        // panicked. write_config now rejects one, so seed it directly to model a
        // blob left by an older build or a corrupt flash — the read must clamp,
        // not panic.
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        fs.put(EF_DEV_CONF, &[0xAB; EF_DEV_CONF_MAX + 16]).unwrap();
        let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        assert_eq!(sw, Sw::OK);
        // Well-formed output, nothing sliced out of bounds.
        assert_eq!(body[0] as usize, body.len() - 1);
    }

    #[test]
    fn write_config_rejects_bad_length() {
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        // First byte (3) disagrees with the actual remaining length (2).
        let (sw, _) = process(
            &mut app,
            &mut fs,
            &[0x00, INS_WRITE_CONFIG, 0, 0, 0x03, 0x03, 0xAA, 0xBB],
        );
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
    }

    #[test]
    fn bad_cla_and_ins_rejected() {
        let mut app = ManagementApplet::new([0; 8]);
        let mut fs = fs();
        let (sw, _) = process(&mut app, &mut fs, &[0x10, INS_READ_CONFIG, 0, 0, 0x00]);
        assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
        let (sw, _) = process(&mut app, &mut fs, &[0x00, 0xEE, 0, 0, 0x00]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
        // RESET is recognised but deferred.
        let (sw, _) = process(&mut app, &mut fs, &[0x00, INS_RESET, 0, 0, 0x00]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    }
}
