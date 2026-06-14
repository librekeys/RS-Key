// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-piv` — the PIV card applet: the NIST SP 800-73-4 command subset plus the
//! Yubico extensions `ykman piv` / `yubico-piv-tool` exercise (metadata, serial,
//! attestation, move/delete, set-mgm-key, set-retries, reset), reached over CCID.
//! Pure and host-testable; key machinery comes from `rsk-openpgp`, private keys
//! at rest are GCM-sealed ([`seal`]), and management operations (IMPORT KEY, PUT
//! DATA, SET MGM KEY, MOVE KEY, SET RETRIES) require management-key auth.

extern crate alloc;

mod auth;
pub mod files;
mod keygen;
mod seal;
mod x509;

use core::cell::RefCell;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
pub use rsk_openpgp::Rng;
use rsk_openpgp::keys::make_rsa_response;
// PIV reuses the OpenPGP user-presence trait, so the firmware's existing
// `impl rsk_openpgp::UserPresence for BootselPresence` already drives PIV touch.
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
pub use rsk_openpgp::{AlwaysConfirm, Presence, UserPresence};
use rsk_sdk::tlv::{find_tag, format_len};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};
use zeroize::Zeroize;

use files::*;

/// The PIV AID prefix the dispatcher matches. The full requested AID is
/// `A0 00 00 03 08 00 00 10 00 01 00`.
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// Reported PIV application version — the shared [`rsk_sdk::FIRMWARE_VERSION`]
/// (default 5.7.4, `FW_VERSION`-overridable).
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Status 0x6A80 (wrong data).
pub(crate) const WRONG_DATA: Sw = Sw::INCORRECT_PARAMS;

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
/// Shared with the OpenPGP GENERATE INS; PIV uses P1 = 0x00 (OpenPGP: 0x80/0x81).
pub const INS_ASYM_KEYGEN: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_SELECT: u8 = 0xA4;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_MOVE_KEY: u8 = 0xF6;
const INS_GET_METADATA: u8 = 0xF7;
const INS_YK_SERIAL: u8 = 0xF8;
const INS_ATTESTATION: u8 = 0xF9;
const INS_SET_RETRIES: u8 = 0xFA;
const INS_RESET: u8 = 0xFB;
const INS_VERSION: u8 = 0xFD;
const INS_IMPORT_ASYM: u8 = 0xFE;
const INS_SET_MGMKEY: u8 = 0xFF;

/// Volatile per-selection security state.
#[derive(Default)]
pub(crate) struct Session {
    pub(crate) has_pin: bool,
    pub(crate) has_mgm: bool,
    pub(crate) has_challenge: bool,
    pub(crate) challenge: [u8; 16],
}

impl Session {
    fn reset(&mut self) {
        self.has_pin = false;
        self.has_mgm = false;
        self.has_challenge = false;
        self.challenge.zeroize();
    }
}

pub struct PivApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned.
    otp_key: Option<[u8; 32]>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    sess: Session,
}

impl<'a> PivApplet<'a> {
    /// `presence` is the BOOTSEL button (shared with the FIDO/OpenPGP/OTP
    /// applets) — it gates the slot/management touch policies.
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        PivApplet {
            serial_id,
            serial_hash,
            otp_key,
            rng,
            presence,
            sess: Session::default(),
        }
    }

    /// Owned copies of the device identifiers, for building a [`Device`] that
    /// does not hold a borrow of `self` across `&mut self` calls.
    fn device_ids(&self) -> ([u8; 32], [u8; 8], Option<[u8; 32]>) {
        (self.serial_hash, self.serial_id, self.otp_key)
    }

    /// If `apdu` is a PIV RSA GENERATE, validate it fully and return the slot,
    /// modulus size and resolved policy bytes so the firmware can run the slow
    /// prime search itself (stepping [`RsaKeygen`] between CCID keepalives).
    /// `None` falls through to normal dispatch — EC generate, or any error
    /// (re-validated there so the right SW is reported).
    pub fn rsa_generate_params<S: Storage>(
        &mut self,
        _fs: &mut Fs<S>,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Option<(u8, usize, [u8; 2])> {
        if p1 != 0x00 || !self.sess.has_mgm || !is_key(p2) {
            return None;
        }
        let req = keygen::parse_gen_template(data).ok()?;
        let nbits = match req.algo {
            ALGO_RSA1024 => 1024,
            ALGO_RSA2048 => 2048,
            _ => return None,
        };
        let pol = keygen::resolved_policies(p2, req.pin_policy, req.touch_policy);
        Some((p2, nbits, pol))
    }

    /// Store the firmware-generated RSA key, certificate and metadata and write
    /// the `7F49` response body + SW into `resp`; returns the total length.
    pub fn rsa_generate_finish<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        rng: &mut dyn Rng,
        slot: u8,
        pol: [u8; 2],
        key: &RsaPrivateKey,
        resp: &mut [u8],
    ) -> (usize, Sw) {
        let algo = if key.size() == 128 {
            ALGO_RSA1024
        } else {
            ALGO_RSA2048
        };
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        };
        let mut res = ResBuf::new(resp);
        let sw = keygen::finish_rsa(&dev, fs, rng, slot, algo, pol, key, &mut res);
        (res.len(), sw)
    }
}

/// The SELECT application property template (`61 { … }`); the outer length
/// byte is filled in (some implementations leave it 0).
fn apt(res: &mut ResBuf) -> Sw {
    const BODY: &[u8] = &[
        0x4F, 0x02, 0x01, 0x00, // application version
        0x79, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, // tag allocation
        0x50, 0x0A, b'R', b'S', b'-', b'K', b'e', b'y', b' ', b'P', b'I',
        b'V', // application label
        0xAC, 0x0C, 0x80, 0x07, 0x07, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0x2E, 0x06, 0x01,
        0x00, // supported algorithms
    ];
    if !res.push(0x61) || !res.push(BODY.len() as u8) || !res.extend(BODY) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

impl<S: Storage> Applet<Fs<S>> for PivApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        PIV_AID
    }

    /// PIV GET DATA (certificates) routinely exceeds 256 bytes; OpenSC/`ykman`
    /// read it with a short `Le` and standard GET RESPONSE, so opt into the
    /// dispatcher's response chaining.
    fn response_chaining(&self) -> bool {
        true
    }

    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        self.sess.reset();
        let (serial_hash, serial_id, otp_key) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: otp_key.as_ref(),
        };
        let mut rng = self.rng.borrow_mut();
        if files::scan_files(&dev, fs, &mut *rng).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        apt(res)
    }

    fn deselect(&mut self, _fs: &mut Fs<S>) {
        self.sess.reset();
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (serial_hash, serial_id, otp_key) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: otp_key.as_ref(),
        };
        match apdu.ins {
            INS_VERSION => {
                res.extend(&[VERSION.0, VERSION.1, VERSION.2]);
                Sw::OK
            }
            INS_YK_SERIAL => {
                res.extend(&rsk_mgmt::serial4(self.serial_id));
                Sw::OK
            }
            INS_SELECT => {
                // A re-SELECT addressed at the applet itself.
                if apdu.p2 != 0x01 {
                    return Sw::WRONG_P1P2;
                }
                if apdu.data.len() >= PIV_AID.len() && &apdu.data[..PIV_AID.len()] == PIV_AID {
                    return apt(res);
                }
                Sw::OK
            }
            INS_VERIFY => self.verify(&dev, fs, apdu, res),
            INS_CHANGE_PIN => self.change_pin(&dev, fs, apdu),
            INS_RESET_RETRY => self.reset_retry(&dev, fs, apdu),
            INS_AUTHENTICATE => {
                let mut rng = self.rng.borrow_mut();
                let mut presence = self.presence.borrow_mut();
                auth::general_authenticate(
                    &mut self.sess,
                    &dev,
                    fs,
                    &mut *rng,
                    &mut *presence,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                    res,
                )
            }
            INS_ASYM_KEYGEN => self.keygen(&dev, fs, apdu, res),
            INS_GET_DATA => self.get_data(fs, apdu, res),
            INS_PUT_DATA => self.put_data(fs, apdu),
            INS_GET_METADATA => self.get_metadata(&dev, fs, apdu, res),
            INS_SET_MGMKEY => self.set_mgmkey(&dev, fs, apdu),
            INS_MOVE_KEY => self.move_key(fs, apdu),
            INS_SET_RETRIES => self.set_retries(&dev, fs, apdu),
            INS_RESET => self.reset(&dev, fs, apdu),
            INS_ATTESTATION => {
                if apdu.p2 != 0x00 {
                    return Sw::INCORRECT_P1P2;
                }
                let mut rng = self.rng.borrow_mut();
                keygen::attest(
                    &dev,
                    fs,
                    &mut *rng,
                    apdu.p1,
                    rsk_mgmt::serial4(self.serial_id),
                    res,
                )
            }
            INS_IMPORT_ASYM => {
                let mut rng = self.rng.borrow_mut();
                keygen::import(&self.sess, &dev, fs, &mut *rng, apdu.p1, apdu.p2, apdu.data)
            }
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

impl PivApplet<'_> {
    /// VERIFY (INS 0x20): the PIV application PIN, reference 0x80.
    fn verify<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        _res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 && apdu.p1 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.p2 != 0x80 {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if !fs.has_data(EF_PIN) {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if apdu.p1 == 0xFF {
            // SP 800-73: reset the security status of the PIN.
            if apdu.nc != 0 {
                return Sw::WRONG_LENGTH;
            }
            self.sess.has_pin = false;
            return Sw::OK;
        }
        if apdu.nc == 0 {
            let left = match retries_left(fs, RETRY_PIN) {
                Ok(l) => l,
                Err(sw) => return sw,
            };
            if left == 0 {
                return Sw::PIN_BLOCKED;
            }
            if self.sess.has_pin {
                return Sw::OK;
            }
            return Sw::new(0x63, 0xC0 | left);
        }
        match check_ref(dev, fs, EF_PIN, RETRY_PIN, apdu.data) {
            Sw::OK => {
                self.sess.has_pin = true;
                Sw::OK
            }
            sw => sw,
        }
    }

    /// CHANGE REFERENCE DATA (INS 0x24): `old ‖ new`, old length taken from
    /// the stored record.
    fn change_pin<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let (fid, retry) = match apdu.p2 {
            0x80 => (EF_PIN, RETRY_PIN),
            0x81 => (EF_PUK, RETRY_PUK),
            _ => return Sw::INCORRECT_P1P2,
        };
        let old_len = match stored_pin_len(fs, fid) {
            Ok(n) => n,
            Err(sw) => return sw,
        };
        if apdu.nc <= old_len {
            return Sw::WRONG_LENGTH;
        }
        let new = &apdu.data[old_len..];
        if new.len() > 8 {
            return Sw::WRONG_LENGTH;
        }
        match check_ref(dev, fs, fid, retry, &apdu.data[..old_len]) {
            Sw::OK => {}
            sw => return sw,
        }
        if put_pin_verifier(dev, fs, fid, new).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        Sw::OK
    }

    /// RESET RETRY COUNTER (INS 0x2C): unblock/replace the PIN with the PUK.
    fn reset_retry<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 || apdu.p2 != 0x80 {
            return Sw::INCORRECT_P1P2;
        }
        let puk_len = match stored_pin_len(fs, EF_PUK) {
            Ok(n) => n,
            Err(sw) => return sw,
        };
        if apdu.nc <= puk_len {
            return Sw::WRONG_LENGTH;
        }
        let new = &apdu.data[puk_len..];
        if new.len() > 8 {
            return Sw::WRONG_LENGTH;
        }
        match check_ref(dev, fs, EF_PUK, RETRY_PUK, &apdu.data[..puk_len]) {
            Sw::OK => {}
            sw => return sw,
        }
        if put_pin_verifier(dev, fs, EF_PIN, new).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        reset_counter(fs, RETRY_PIN)
    }

    /// SET RETRIES (INS 0xFA, management-gated): resets both references to
    /// their defaults with the new totals.
    fn set_retries<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if apdu.p1 == 0 || apdu.p2 == 0 {
            return Sw::INCORRECT_PARAMS;
        }
        if fs
            .put(EF_RETRIES, &[apdu.p1, apdu.p1, apdu.p2, apdu.p2])
            .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        if put_pin_verifier(dev, fs, EF_PIN, &DEFAULT_PIN).is_err()
            || put_pin_verifier(dev, fs, EF_PUK, &DEFAULT_PUK).is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        self.sess.has_pin = false;
        Sw::OK
    }

    /// RESET (INS 0xFB): only with both references blocked.
    fn reset<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let (pin_left, puk_left) = match (retries_left(fs, RETRY_PIN), retries_left(fs, RETRY_PUK))
        {
            (Ok(p), Ok(k)) => (p, k),
            _ => return Sw::REFERENCE_NOT_FOUND,
        };
        if pin_left != 0 || puk_left != 0 {
            return Sw::INCORRECT_PARAMS;
        }
        let mut rng = self.rng.borrow_mut();
        if files::reset_files(dev, fs, &mut *rng).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        self.sess.reset();
        Sw::OK
    }

    /// GENERATE ASYMMETRIC KEY PAIR (INS 0x47). EC runs inline; RSA normally
    /// arrives via the firmware fast-path, with a blocking fallback for host use.
    fn keygen<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.nc == 0 {
            return Sw::WRONG_LENGTH;
        }
        if apdu.data[0] != 0xAC {
            return WRONG_DATA;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if !is_key(apdu.p2) {
            return Sw::INCORRECT_P1P2;
        }
        let req = match keygen::parse_gen_template(apdu.data) {
            Ok(r) => r,
            Err(sw) => return sw,
        };
        let mut rng = self.rng.borrow_mut();
        match req.algo {
            ALGO_ECCP256 | ALGO_ECCP384 => {
                keygen::generate_ec(dev, fs, &mut *rng, apdu.p2, &req, res)
            }
            ALGO_RSA1024 | ALGO_RSA2048 => {
                keygen::generate_rsa_blocking(dev, fs, &mut *rng, apdu.p2, &req, res)
            }
            // X25519 generation is unsupported: fail rather than store nothing.
            _ => WRONG_DATA,
        }
    }

    /// GET DATA (INS 0xCB).
    fn get_data<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu, res: &mut ResBuf) -> Sw {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        let d = apdu.data;
        if d.len() < 3 || d[0] != 0x5C {
            return WRONG_DATA;
        }
        let l = d[1] as usize;
        if l == 0 || l > 3 || d.len() < 2 + l {
            return WRONG_DATA;
        }
        let mut id: u32 = 0;
        for &b in &d[2..2 + l] {
            id = id << 8 | b as u32;
        }
        if id == DISCOVERY_ID {
            res.extend(DISCOVERY);
            return Sw::OK;
        }
        let Some(fid) = object_fid(id) else {
            return Sw::FILE_NOT_FOUND;
        };
        let mut obj = [0u8; MAX_OBJECT];
        let n = match fs.read(fid, &mut obj) {
            Some(n) if n > 0 => n,
            _ => return Sw::FILE_NOT_FOUND,
        };
        if push_tlv(res, 0x53, &obj[..n]).is_err() {
            return Sw::WRONG_LENGTH;
        }
        Sw::OK
    }

    /// PUT DATA (INS 0xDB, management-gated).
    fn put_data<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // Discovery / biometric writes are acknowledged with a bare OK (not stored).
        if !apdu.data.is_empty() && (apdu.data[0] == 0x7E || apdu.data[0] == 0x7F) {
            return Sw::OK;
        }
        let (Some(path), Some(obj)) = (find_tag(apdu.data, 0x5C), find_tag(apdu.data, 0x53)) else {
            return WRONG_DATA;
        };
        if path.len() != 3 || path[0] != 0x5F || path[1] != 0xC1 {
            return WRONG_DATA;
        }
        let fid = 0xD200 | path[2] as u16;
        if obj.is_empty() {
            let _ = fs.delete(fid);
            return Sw::OK;
        }
        if obj.len() > MAX_OBJECT {
            return Sw::WRONG_LENGTH;
        }
        if fs.put(fid, obj).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        Sw::OK
    }

    /// GET METADATA (INS 0xF7, Yubico).
    fn get_metadata<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let key_ref = apdu.p2;
        match key_ref {
            0x80 | 0x81 => {
                let (fid, retry, default) = if key_ref == 0x80 {
                    (EF_PIN, RETRY_PIN, &DEFAULT_PIN)
                } else {
                    (EF_PUK, RETRY_PUK, &DEFAULT_PUK)
                };
                let mut rec = [0u8; 34];
                let Some(34) = fs.read(fid, &mut rec) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                let is_default = ct_eq(&rec[2..34], &dev.pin_derive_verifier(default));
                let (total, left) = match retries(fs, retry) {
                    Ok(t) => t,
                    Err(sw) => return sw,
                };
                res.extend(&[0x05, 0x01, is_default as u8]);
                res.extend(&[0x06, 0x02, total, left]);
                Sw::OK
            }
            SLOT_CARDMGM => {
                let mut meta = [0u8; 8];
                let Some(n) = fs.meta_find(key_fid(SLOT_CARDMGM), &mut meta) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                if n < 3 {
                    return Sw::REFERENCE_NOT_FOUND;
                }
                let mut key = [0u8; 32];
                let is_default = match seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut key) {
                    Ok(24) => ct_eq(&key[..24], &DEFAULT_MGM),
                    Ok(_) => false,
                    Err(sw) => return sw,
                };
                key.zeroize();
                res.extend(&[0x01, 0x01, meta[0]]);
                res.extend(&[0x02, 0x02, meta[1], meta[2]]);
                res.extend(&[0x05, 0x01, is_default as u8]);
                Sw::OK
            }
            s if is_key(s) => {
                if !fs.has_data(key_fid(s)) {
                    return Sw::REFERENCE_NOT_FOUND;
                }
                let mut meta = [0u8; 8];
                let Some(n) = fs.meta_find(key_fid(s), &mut meta) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                if n < 4 {
                    return Sw::REFERENCE_NOT_FOUND;
                }
                res.extend(&[0x01, 0x01, meta[0]]);
                res.extend(&[0x02, 0x02, meta[1], meta[2]]);
                res.extend(&[0x03, 0x01, meta[3]]);
                self.slot_pubkey_tlv(dev, fs, s, meta[0], res)
            }
            _ => Sw::REFERENCE_NOT_FOUND,
        }
    }

    /// Metadata tag 0x04: the slot public key as `81/82` (RSA) or `86` (EC)
    /// TLVs, the encoding `yubikit` expects.
    fn slot_pubkey_tlv<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        slot: u8,
        algo: u8,
        res: &mut ResBuf,
    ) -> Sw {
        let mut body = [0u8; 5 + 4 + 256 + 2 + 8];
        let n = match algo {
            ALGO_RSA1024 | ALGO_RSA2048 => {
                let key = match seal::load_rsa_key(dev, fs, key_fid(slot)) {
                    Ok(k) => k,
                    Err(_) => return Sw::EXEC_ERROR,
                };
                // `make_rsa_response` emits `7F49 82 LL { 81 … 82 … }`; reuse
                // its body, skipping the 5-byte 7F49 header.
                let full = make_rsa_response(&key, &mut body);
                body.copy_within(5..full, 0);
                full - 5
            }
            ALGO_ECCP256 | ALGO_ECCP384 => {
                let key = match seal::load_ec_key(dev, fs, key_fid(slot)) {
                    Ok(k) => k,
                    Err(_) => return Sw::EXEC_ERROR,
                };
                let mut point = [0u8; 97];
                let plen = match key.public_point(&mut point) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                body[0] = 0x86;
                let ll = format_len(plen as u16, &mut body[1..4]);
                body[1 + ll..1 + ll + plen].copy_from_slice(&point[..plen]);
                1 + ll + plen
            }
            _ => return Sw::REFERENCE_NOT_FOUND,
        };
        if push_tlv(res, 0x04, &body[..n]).is_err() {
            return Sw::WRONG_LENGTH;
        }
        Sw::OK
    }

    /// SET MGM KEY (INS 0xFF, management-gated).
    fn set_mgmkey<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        let touch = match apdu.p2 {
            0xFF => TOUCHPOLICY_NEVER,
            0xFE => TOUCHPOLICY_ALWAYS,
            _ => return Sw::INCORRECT_P1P2,
        };
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if apdu.nc < 5 {
            return Sw::WRONG_LENGTH;
        }
        let (algo, key_ref, klen) = (apdu.data[0], apdu.data[1], apdu.data[2] as usize);
        // The FIPS-style profile refuses *new* 3DES management keys
        // (SP 800-131A); an existing 3DES key still authenticates, so a
        // reflashed device can migrate itself to AES.
        let tdes = cfg!(not(feature = "fips-profile"));
        let len_ok = matches!(
            (algo, klen),
            (ALGO_AES128, 16) | (ALGO_AES192, 24) | (ALGO_AES256, 32)
        ) || (tdes && (algo, klen) == (ALGO_3DES, 24));
        if key_ref != SLOT_CARDMGM || !len_ok {
            return WRONG_DATA;
        }
        if apdu.nc != 3 + klen {
            return Sw::WRONG_LENGTH;
        }
        let mut rng = self.rng.borrow_mut();
        if seal::seal_put(
            dev,
            fs,
            &mut *rng,
            key_fid(SLOT_CARDMGM),
            &apdu.data[3..3 + klen],
        )
        .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        let mut meta = [0u8; 8];
        let Some(n) = fs.meta_find(key_fid(SLOT_CARDMGM), &mut meta) else {
            return Sw::REFERENCE_NOT_FOUND;
        };
        if n < 3 {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if fs
            .meta_add(key_fid(SLOT_CARDMGM), &[algo, meta[1], touch])
            .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        Sw::OK
    }

    /// MOVE KEY (INS 0xF6, Yubico 5.7, management-gated): move (or, to 0xFF,
    /// delete) a key with its certificate object and metadata.
    fn move_key<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let (to, from) = (apdu.p1, apdu.p2);
        if (!is_key(to) && to != 0xFF) || !is_key(from) {
            return Sw::INCORRECT_P1P2;
        }
        if is_retired(from) && is_active(to) {
            return Sw::INCORRECT_P1P2;
        }
        // The sealed blob is bound to the device, not the fid, so it moves
        // verbatim.
        let mut blob = [0u8; 300];
        let Some(blob_n) = fs.read(key_fid(from), &mut blob) else {
            return Sw::FILE_NOT_FOUND;
        };
        let (cert_from, cert_to) = (cert_fid_for_slot(from), cert_fid_for_slot(to));
        if to != 0xFF {
            if fs.put(key_fid(to), &blob[..blob_n]).is_err() {
                blob.zeroize();
                return Sw::MEMORY_FAILURE;
            }
            let mut obj = [0u8; MAX_OBJECT];
            let cert = cert_from.and_then(|f| fs.read(f, &mut obj));
            if let (Some(n), Some(tofid)) = (cert, cert_to) {
                if fs.put(tofid, &obj[..n]).is_err() {
                    blob.zeroize();
                    return Sw::MEMORY_FAILURE;
                }
            } else if let Some(tofid) = cert_to {
                let _ = fs.delete(tofid);
            }
            let mut meta = [0u8; 8];
            match fs.meta_find(key_fid(from), &mut meta) {
                Some(n) => {
                    if fs.meta_add(key_fid(to), &meta[..n]).is_err() {
                        blob.zeroize();
                        return Sw::MEMORY_FAILURE;
                    }
                }
                None => {
                    let _ = fs.meta_delete(key_fid(to));
                }
            }
        }
        blob.zeroize();
        let _ = fs.delete(key_fid(from));
        if let Some(f) = cert_from {
            let _ = fs.delete(f);
        }
        let _ = fs.meta_delete(key_fid(from));
        Sw::OK
    }
}

/// Largest stored data-object body (certificate objects included); bounded so
/// the `53`-wrapped response fits the 2 KiB CCID response buffer.
const MAX_OBJECT: usize = 1900;

const RETRY_PIN: usize = 0;
const RETRY_PUK: usize = 2;

fn retries<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Result<(u8, u8), Sw> {
    let mut r = [0u8; 4];
    let Some(4) = fs.read(EF_RETRIES, &mut r) else {
        return Err(Sw::REFERENCE_NOT_FOUND);
    };
    Ok((r[idx], r[idx + 1]))
}

fn retries_left<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Result<u8, Sw> {
    retries(fs, idx).map(|(_, l)| l)
}

fn set_retries_left<S: Storage>(fs: &mut Fs<S>, idx: usize, left: u8) -> Result<(), Sw> {
    let mut r = [0u8; 4];
    let Some(4) = fs.read(EF_RETRIES, &mut r) else {
        return Err(Sw::REFERENCE_NOT_FOUND);
    };
    r[idx + 1] = left;
    fs.put(EF_RETRIES, &r).map_err(|_| Sw::MEMORY_FAILURE)
}

fn reset_counter<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Sw {
    match retries(fs, idx) {
        Ok((total, _)) => match set_retries_left(fs, idx, total) {
            Ok(()) => Sw::OK,
            Err(sw) => sw,
        },
        Err(sw) => sw,
    }
}

fn stored_pin_len<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<usize, Sw> {
    let mut rec = [0u8; 34];
    let Some(34) = fs.read(fid, &mut rec) else {
        return Err(Sw::MEMORY_FAILURE);
    };
    Ok(rec[0] as usize)
}

/// Boot-pass migration: re-seal every sealed PIV key slot under the OTP kbase
/// (no-op without the OTP key). PIN/PUK verifiers migrate lazily at their own
/// verify instead — they are one-way derivations of the PIN.
pub fn migrate_kbase<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    seal::migrate_kbase(dev, fs, rng)
}

/// Verify a PIN/PUK against its stored verifier, with the retry dance —
/// decrement on mismatch (`63Cx`, `6983` at zero), reset on success.
fn check_ref<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: u16, retry: usize, pin: &[u8]) -> Sw {
    let (total, left) = match retries(fs, retry) {
        Ok(t) => t,
        Err(sw) => return sw,
    };
    if left == 0 {
        return Sw::PIN_BLOCKED;
    }
    let mut rec = [0u8; 34];
    let Some(34) = fs.read(fid, &mut rec) else {
        return Sw::MEMORY_FAILURE;
    };
    let ver = dev.pin_derive_verifier(pin);
    let mut matched = ct_eq(&ver, &rec[2..34]);
    if !matched
        && dev.otp_key.is_some()
        && ct_eq(&dev.without_otp().pin_derive_verifier(pin), &rec[2..34])
    {
        // kbase-migration fallback: the correct PIN against a verifier stored
        // before the OTP key was provisioned — re-store it under the OTP arm
        // (sealed key slots migrate in the boot pass, not here).
        if put_pin_verifier(dev, fs, fid, pin).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        matched = true;
    }
    if matched {
        if set_retries_left(fs, retry, total).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        return Sw::OK;
    }
    let left = left - 1;
    if set_retries_left(fs, retry, left).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    if left == 0 {
        Sw::PIN_BLOCKED
    } else {
        Sw::new(0x63, 0xC0 | left)
    }
}

/// Constant-time slice equality (length public).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Append `tag { payload }` with a DER length to `res`.
pub(crate) fn push_tlv(res: &mut ResBuf, tag: u8, payload: &[u8]) -> Result<(), Sw> {
    let mut ll = [0u8; 3];
    let n = format_len(payload.len() as u16, &mut ll);
    if !res.push(tag) || !res.extend(&ll[..n]) || !res.extend(payload) {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok(())
}

/// Build the GENERAL AUTHENTICATE response `7C { tag payload }`.
pub(crate) fn dyn_auth_resp(res: &mut ResBuf, tag: u8, payload: &[u8]) -> Result<(), Sw> {
    let mut ll = [0u8; 3];
    let inner = 1 + format_len(payload.len() as u16, &mut ll) as u16 + payload.len() as u16;
    let mut oll = [0u8; 3];
    let on = format_len(inner, &mut oll);
    if !res.push(0x7C) || !res.extend(&oll[..on]) {
        return Err(Sw::WRONG_LENGTH);
    }
    push_tlv(res, tag, payload)
}

/// Wrap a DER certificate as the Yubico certificate object
/// `70 { cert } 71 { 0 } FE { }` (uncompressed).
pub fn wrap_cert_object(cert: &[u8], out: &mut [u8]) -> usize {
    let mut p = 0;
    out[p] = 0x70;
    p += 1;
    let mut ll = [0u8; 3];
    let n = format_len(cert.len() as u16, &mut ll);
    out[p..p + n].copy_from_slice(&ll[..n]);
    p += n;
    out[p..p + cert.len()].copy_from_slice(cert);
    p += cert.len();
    out[p..p + 5].copy_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    p + 5
}

/// Adapts [`Rng`] to `rand_core` for the `rsa` crate's blinded private op.
pub(crate) struct RngAdapter<'a>(pub(crate) &'a mut dyn Rng);

impl rsa::rand_core::RngCore for RngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.fill(dst);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for RngAdapter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest;

    const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const HASH: [u8; 32] = [0x22; 32];

    /// Deterministic LCG randomness — good enough for nonces and prime search.
    struct TestRng(u64);
    impl Rng for TestRng {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *x = (self.0 >> 33) as u8;
            }
        }
    }

    fn new_fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    fn select(app: &mut PivApplet, fs: &mut Fs<RamStorage>) -> Vec<u8> {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::select(app, false, fs, &mut res);
        assert_eq!(sw, Sw::OK);
        res.as_slice().to_vec()
    }

    fn apdu_bytes(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut raw = vec![0x00, ins, p1, p2];
        if data.is_empty() {
        } else if data.len() <= 255 {
            raw.push(data.len() as u8);
            raw.extend_from_slice(data);
        } else {
            raw.push(0);
            raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
            raw.extend_from_slice(data);
        }
        raw
    }

    fn run(
        app: &mut PivApplet,
        fs: &mut Fs<RamStorage>,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> (Sw, Vec<u8>) {
        let raw = apdu_bytes(ins, p1, p2, data);
        let apdu = Apdu::parse(&raw).unwrap();
        let mut out = [0u8; 2048];
        let mut res = ResBuf::new(&mut out);
        let sw = Applet::process(app, &apdu, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    /// Mutual-auth against the default AES-192 management key.
    fn auth_mgm(app: &mut PivApplet, fs: &mut Fs<RamStorage>) {
        let (sw, wit) = run(
            app,
            fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            0x9B,
            &[0x7C, 0x02, 0x80, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(&wit[..4], &[0x7C, 0x12, 0x80, 0x10]);
        let mut w: [u8; 16] = wit[4..20].try_into().unwrap();
        rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut w).unwrap();
        let host_chal = [0xA5u8; 16];
        let mut msg = vec![0x7C, 0x24, 0x80, 0x10];
        msg.extend_from_slice(&w);
        msg.push(0x81);
        msg.push(0x10);
        msg.extend_from_slice(&host_chal);
        let (sw, resp) = run(app, fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&resp[..4], &[0x7C, 0x12, 0x82, 0x10]);
        let mut expect = host_chal;
        rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut expect).unwrap();
        assert_eq!(&resp[4..20], &expect);
    }

    fn verify_pin(app: &mut PivApplet, fs: &mut Fs<RamStorage>) {
        let (sw, _) = run(app, fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
        assert_eq!(sw, Sw::OK);
    }

    fn gen_template(algo: u8) -> Vec<u8> {
        vec![0xAC, 0x03, 0x80, 0x01, algo]
    }

    /// Presence stand-in whose answer the test flips between calls.
    struct Scripted {
        confirm: bool,
    }
    impl UserPresence for Scripted {
        fn request(&mut self) -> Presence {
            if self.confirm {
                Presence::Confirmed
            } else {
                Presence::Declined
            }
        }
    }

    /// Extract `point` from the keygen response `7F49 { 86 point }` (P-256 and
    /// P-384 bodies use short-form lengths).
    fn ec_point_of(resp: &[u8]) -> Vec<u8> {
        assert_eq!(&resp[..2], &[0x7F, 0x49]);
        let body = &resp[3..];
        assert_eq!(body[0], 0x86);
        let plen = body[1] as usize;
        body[2..2 + plen].to_vec()
    }

    #[test]
    fn touch_policy_enforced_on_slot_sign() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(Scripted { confirm: true });
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        // Management auth: default mgm touch is NEVER, so no touch is consulted.
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        // Generate a P-256 key in 9A — default touch policy ALWAYS.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x02).unwrap()[1], TOUCHPOLICY_ALWAYS);
        let digest = [0x42u8; 32];
        let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
        msg.extend_from_slice(&digest);
        // Touch declined → the sign is refused.
        pres.borrow_mut().confirm = false;
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9A,
            &msg,
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        // Touch confirmed → it proceeds.
        pres.borrow_mut().confirm = true;
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9A,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn touch_policy_never_skips_presence() {
        // A slot generated with an explicit touch policy NEVER must not consult
        // presence — a declining button still lets the sign through.
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(Scripted { confirm: false });
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        // AC template with touch policy tag 0xAB = NEVER.
        let tmpl = vec![
            0xAC,
            0x06,
            0x80,
            0x01,
            ALGO_ECCP256,
            0xAB,
            0x01,
            TOUCHPOLICY_NEVER,
        ];
        let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9E, &tmpl);
        assert_eq!(sw, Sw::OK);
        let digest = [0x42u8; 32];
        let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
        msg.extend_from_slice(&digest);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9E,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn select_returns_apt() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        let apt = select(&mut app, &mut fs);
        assert_eq!(apt[0], 0x61);
        assert_eq!(apt[1] as usize, apt.len() - 2, "APT length backpatched");
        let body = &apt[2..];
        assert!(find_tag(body, 0x4F).is_some());
        assert_eq!(find_tag(body, 0x50).unwrap(), b"RS-Key PIV");
        assert!(find_tag(body, 0xAC).is_some());
    }

    #[test]
    fn version_and_serial() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let (sw, v) = run(&mut app, &mut fs, INS_VERSION, 0, 0, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(v, vec![5, 7, 4]);
        let (sw, s) = run(&mut app, &mut fs, INS_YK_SERIAL, 0, 0, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(s, rsk_mgmt::serial4(SERIAL).to_vec());
    }

    #[test]
    fn pin_verify_retry_and_unblock() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        // Retry query on a fresh card.
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
        assert_eq!(sw, Sw::new(0x63, 0xC3));
        // Wrong PIN decrements.
        let wrong = [0x39u8; 8];
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
        assert_eq!(sw, Sw::new(0x63, 0xC2));
        verify_pin(&mut app, &mut fs);
        // Success resets the counter and satisfies the empty-data query.
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
        assert_eq!(sw, Sw::OK);
        // P1=FF drops the security state.
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, &[]);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
        assert_eq!(sw, Sw::new(0x63, 0xC3));
        // Block the PIN, then unblock with the PUK.
        for left in [2, 1] {
            let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
            assert_eq!(sw, Sw::new(0x63, 0xC0 | left));
        }
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
        assert_eq!(sw, Sw::PIN_BLOCKED);
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
        assert_eq!(sw, Sw::PIN_BLOCKED);
        let mut unblock = DEFAULT_PUK.to_vec();
        let newpin = *b"654321\xff\xff";
        unblock.extend_from_slice(&newpin);
        let (sw, _) = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &unblock);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &newpin);
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn change_pin_and_puk() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let newpin = *b"00112233";
        let mut msg = DEFAULT_PIN.to_vec();
        msg.extend_from_slice(&newpin);
        let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &newpin);
        assert_eq!(sw, Sw::OK);
        // Wrong old PIN burns a retry and reports it.
        let mut bad = DEFAULT_PIN.to_vec();
        bad.extend_from_slice(b"99999999");
        let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &bad);
        assert_eq!(sw, Sw::new(0x63, 0xC2));
        // PUK change.
        let mut msg = DEFAULT_PUK.to_vec();
        msg.extend_from_slice(b"87654321");
        let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x81, &msg);
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn mgm_mutual_auth_gates_keygen() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(&resp[..2], &[0x7F, 0x49]);
    }

    #[test]
    fn mgm_single_auth() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let (sw, chal) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            0x9B,
            &[0x7C, 0x02, 0x81, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(&chal[..4], &[0x7C, 0x12, 0x81, 0x10]);
        let mut enc: [u8; 16] = chal[4..20].try_into().unwrap();
        rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut enc).unwrap();
        let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
        msg.extend_from_slice(&enc);
        let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
        assert_eq!(sw, Sw::OK);
        // The gate is open now.
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9D,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn mgm_single_auth_wrong_response_fails() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            0x9B,
            &[0x7C, 0x02, 0x81, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
        msg.extend_from_slice(&[0u8; 16]);
        let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
        assert_eq!(sw, Sw::DATA_INVALID);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[cfg(feature = "fips-profile")]
    #[test]
    fn fips_refuses_3des_mgm_and_rsa1024() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        // A new 3DES management key is refused (SP 800-131A)…
        let mut msg = vec![ALGO_3DES, 0x9B, 24];
        msg.extend_from_slice(&DEFAULT_MGM);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
        assert_eq!(sw, WRONG_DATA);
        // …and so is RSA-1024 generation.
        let tmpl = [0xAC, 0x03, 0x80, 0x01, ALGO_RSA1024];
        let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, &tmpl);
        assert_eq!(sw, WRONG_DATA);
        // AES management keys are unaffected.
        let mut msg = vec![ALGO_AES256, 0x9B, 32];
        msg.extend_from_slice(&[0x11; 32]);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn mgm_3des_roundtrip() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        // Switch the management key to 3DES (same bytes, new type).
        let mut msg = vec![ALGO_3DES, 0x9B, 24];
        msg.extend_from_slice(&DEFAULT_MGM);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
        assert_eq!(sw, Sw::OK);
        // Metadata reports the new type and no longer claims default…
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_3DES]);
        // …well, the bytes ARE the default key, just typed 3DES.
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
        // Mutual auth over 8-byte 3DES blocks with well-formed TLVs.
        let (sw, wit) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_3DES,
            0x9B,
            &[0x7C, 0x02, 0x80, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(&wit[..4], &[0x7C, 0x0A, 0x80, 0x08]);
        let mut w: [u8; 8] = wit[4..12].try_into().unwrap();
        let key24: [u8; 24] = DEFAULT_MGM;
        rsk_crypto::des3_decrypt_block(&key24, &mut w);
        let host_chal = [0x5Au8; 8];
        let mut msg = vec![0x7C, 0x14, 0x80, 0x08];
        msg.extend_from_slice(&w);
        msg.push(0x81);
        msg.push(0x08);
        msg.extend_from_slice(&host_chal);
        let (sw, resp) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_3DES, 0x9B, &msg);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&resp[..4], &[0x7C, 0x0A, 0x82, 0x08]);
        let mut expect = host_chal;
        rsk_crypto::des3_encrypt_block(&key24, &mut expect);
        assert_eq!(&resp[4..12], &expect);
    }

    #[test]
    fn keygen_p256_sign_and_verify() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let point = ec_point_of(&resp);
        assert_eq!(point.len(), 65);
        // Slot metadata.
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
        assert_eq!(
            find_tag(&md, 0x02).unwrap(),
            &[PINPOLICY_ONCE, TOUCHPOLICY_ALWAYS]
        );
        assert_eq!(find_tag(&md, 0x03).unwrap(), &[ORIGIN_GENERATED]);
        let pk = find_tag(&md, 0x04).unwrap();
        assert_eq!(find_tag(pk, 0x86).unwrap(), &point[..]);
        // Sign a digest, verify with the returned point.
        let digest: [u8; 32] = sha2::Sha256::digest(b"piv test message").into();
        let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
        msg.extend_from_slice(&digest);
        let (sw, sig) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9A,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
        let dyn_auth = find_tag(&sig, 0x7C).unwrap();
        let der = find_tag(dyn_auth, 0x82).unwrap().to_vec();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        let psig = p256::ecdsa::Signature::from_der(&der).unwrap();
        vk.verify_prehash(&digest, &psig).unwrap();
    }

    #[test]
    fn pin_policy_always_on_signature_slot() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9C,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let digest = [0x42u8; 32];
        let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
        msg.extend_from_slice(&digest);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9C,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
        // PIN-always: the second signature needs a fresh VERIFY.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9C,
            &msg,
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9C,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
    }

    #[test]
    fn cert_object_is_wrapped_and_parses() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let point = ec_point_of(&resp);
        let (sw, obj) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
        );
        assert_eq!(sw, Sw::OK);
        let body = find_tag(&obj, 0x53).unwrap();
        let cert = find_tag(body, 0x70).unwrap();
        assert_eq!(find_tag(body, 0x71).unwrap(), &[0x00]);
        let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
        assert!(
            parsed
                .subject()
                .to_string()
                .contains("CN=RS-Key PIV Slot 9A")
        );
        // Self-signature verifies against the slot public key.
        let digest: [u8; 32] = sha2::Sha256::digest(parsed.tbs_certificate.as_ref()).into();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        let sig = p256::ecdsa::Signature::from_der(&parsed.signature_value.data).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();
    }

    #[test]
    fn attestation_chains_to_f9() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, att) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
        assert_eq!(sw, Sw::OK);
        let (_, att_cert) = x509_parser::parse_x509_certificate(&att).unwrap();
        assert!(
            att_cert
                .subject()
                .to_string()
                .contains("CN=RS-Key PIV Attestation 9A")
        );
        assert!(
            att_cert
                .issuer()
                .to_string()
                .contains("CN=RS-Key PIV Slot F9")
        );
        // The Yubico statement extensions are present.
        let oids: Vec<String> = att_cert
            .extensions()
            .iter()
            .map(|e| e.oid.to_id_string())
            .collect();
        for oid in [
            "1.3.6.1.4.1.41482.3.3",
            "1.3.6.1.4.1.41482.3.7",
            "1.3.6.1.4.1.41482.3.8",
            "1.3.6.1.4.1.41482.3.9",
        ] {
            assert!(oids.iter().any(|o| o == oid), "{oid} missing");
        }
        // The F9 certificate object verifies the attestation signature.
        let (sw, f9obj) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
        );
        assert_eq!(sw, Sw::OK);
        let f9cert = find_tag(find_tag(&f9obj, 0x53).unwrap(), 0x70).unwrap();
        let (_, f9) = x509_parser::parse_x509_certificate(f9cert).unwrap();
        let spk = &f9.tbs_certificate.subject_pki.subject_public_key.data;
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(spk).unwrap();
        let digest: [u8; 32] = sha2::Sha256::digest(att_cert.tbs_certificate.as_ref()).into();
        let sig = p384::ecdsa::Signature::from_der(&att_cert.signature_value.data).unwrap();
        use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
        vk.verify_prehash(&digest, &sig).unwrap();
        // An imported key must not attest.
        let scalar = [0x11u8; 32];
        let mut imp = vec![0x06, 32];
        imp.extend_from_slice(&scalar);
        let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9D, 0, &[]);
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
    }

    #[test]
    fn ecdh_on_key_management_slot() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9D,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let card_point = ec_point_of(&resp);
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let host_sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let host_pub_unc = host_sk.public_key().to_encoded_point(false);
        let mut msg = vec![0x7C, 0x45, 0x82, 0x00, 0x85, 0x41];
        msg.extend_from_slice(host_pub_unc.as_bytes());
        let (sw, out) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9D,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
        let dyn_auth = find_tag(&out, 0x7C).unwrap();
        let shared = find_tag(dyn_auth, 0x82).unwrap().to_vec();
        // Host-side ECDH against the card's public point.
        let card_pub = p256::PublicKey::from_sec1_bytes(&card_point).unwrap();
        let host_shared =
            p256::ecdh::diffie_hellman(host_sk.to_nonzero_scalar(), card_pub.as_affine());
        assert_eq!(shared, host_shared.raw_secret_bytes().as_slice());
    }

    #[test]
    fn rsa1024_keygen_sign_verify_and_metadata() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_RSA1024),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(&resp[..2], &[0x7F, 0x49]);
        let body = &resp[5..];
        assert_eq!(body[0], 0x81);
        assert_eq!(body[1], 0x82);
        let nlen = u16::from_be_bytes([body[2], body[3]]) as usize;
        let n_bytes = &body[4..4 + nlen];
        assert_eq!(nlen, 128);
        // Build a PKCS#1 v1.5 EM for SHA-256 and have the card run the raw op.
        let digest: [u8; 32] = sha2::Sha256::digest(b"rsa piv").into();
        let mut em = vec![0x00, 0x01];
        let di = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let pad = 128 - 3 - di.len() - digest.len();
        em.extend(core::iter::repeat_n(0xFF, pad));
        em.push(0x00);
        em.extend_from_slice(&di);
        em.extend_from_slice(&digest);
        assert_eq!(em.len(), 128);
        let mut msg = vec![0x7C, 0x81, 0x85, 0x82, 0x00, 0x81, 0x81, 0x80];
        msg.extend_from_slice(&em);
        let (sw, out) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_RSA1024,
            0x9A,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
        let dyn_auth = find_tag(&out, 0x7C).unwrap();
        let sig = find_tag(dyn_auth, 0x82).unwrap().to_vec();
        assert_eq!(sig.len(), 128);
        // Verify the raw op: sig^e mod n must reproduce the EM (the leading
        // 0x00 is dropped by to_bytes_be).
        let n = rsa::BigUint::from_bytes_be(n_bytes);
        let m = rsa::BigUint::from_bytes_be(&sig).modpow(&rsa::BigUint::from(65537u32), &n);
        assert_eq!(m.to_bytes_be(), em[1..]);
        // Metadata exposes the same modulus.
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
        assert_eq!(sw, Sw::OK);
        let pk = find_tag(&md, 0x04).unwrap();
        assert_eq!(find_tag(pk, 0x81).unwrap(), n_bytes);
        // The self-signed RSA certificate parses, names the slot and is signed
        // sha256WithRSAEncryption.
        let (sw, obj) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
        );
        assert_eq!(sw, Sw::OK);
        let cert = find_tag(find_tag(&obj, 0x53).unwrap(), 0x70).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
        assert!(
            parsed
                .subject()
                .to_string()
                .contains("CN=RS-Key PIV Slot 9A")
        );
        assert_eq!(
            parsed.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.113549.1.1.11"
        );
        // RSA-slot attestation: the P-384 F9 key signs with ecdsa-with-SHA256.
        let (sw, att) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
        assert_eq!(sw, Sw::OK);
        let (_, att_cert) = x509_parser::parse_x509_certificate(&att).unwrap();
        assert_eq!(
            att_cert.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.2"
        );
    }

    #[test]
    fn rsa_import_and_sign() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let key = {
            let mut krng = TestRng(99);
            rsk_openpgp::keys::generate_rsa(&mut krng, 1024).unwrap()
        };
        use rsa::traits::PrivateKeyParts as _;
        let primes = key.primes();
        let p = primes[0].to_bytes_be();
        let q = primes[1].to_bytes_be();
        let mut imp = vec![0x01, p.len() as u8];
        imp.extend_from_slice(&p);
        imp.push(0x02);
        imp.push(q.len() as u8);
        imp.extend_from_slice(&q);
        let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_RSA1024, 0x9E, &imp);
        assert_eq!(sw, Sw::OK);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9E, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x03).unwrap(), &[ORIGIN_IMPORTED]);
        use rsa::traits::PublicKeyParts as _;
        assert_eq!(
            find_tag(find_tag(&md, 0x04).unwrap(), 0x81).unwrap(),
            key.n().to_bytes_be()
        );
    }

    #[test]
    fn objects_roundtrip_and_discovery() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        // Discovery needs no auth and is served raw.
        let (sw, disc) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x01, 0x7E],
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(disc, DISCOVERY);
        // PUT is management-gated.
        let chuid = [0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA];
        let mut put = vec![0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, chuid.len() as u8];
        put.extend_from_slice(&chuid);
        let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        auth_mgm(&mut app, &mut fs);
        let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put);
        assert_eq!(sw, Sw::OK);
        let (sw, obj) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x02],
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&obj, 0x53).unwrap(), &chuid);
        // Empty 53 deletes; reads then 6A82.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x02],
        );
        assert_eq!(sw, Sw::FILE_NOT_FOUND);
        // Unknown object id.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0x00, 0x01],
        );
        assert_eq!(sw, Sw::FILE_NOT_FOUND);
    }

    #[test]
    fn pin_metadata_shapes() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
        assert_eq!(find_tag(&md, 0x06).unwrap(), &[3, 3]);
        // Change the PIN: no longer default, and a burnt retry shows up.
        let mut msg = DEFAULT_PIN.to_vec();
        msg.extend_from_slice(b"violets8");
        let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
        assert_eq!(sw, Sw::new(0x63, 0xC2));
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[0]);
        assert_eq!(find_tag(&md, 0x06).unwrap(), &[3, 2]);
        // Management-key metadata shape.
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_AES192]);
        // Default management key ships touch-OFF (real-YubiKey behaviour).
        assert_eq!(
            find_tag(&md, 0x02).unwrap(),
            &[PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER]
        );
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
    }

    #[test]
    fn move_and_delete_key() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        // Move 9A → retired 0x82.
        let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x82, 0x9A, &[]);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
        // The certificate object moved with it.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
        );
        assert_eq!(sw, Sw::FILE_NOT_FOUND);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x0D],
        );
        assert_eq!(sw, Sw::OK);
        // Retired → active is rejected; delete works.
        let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x82, &[]);
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0xFF, 0x82, &[]);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
    }

    #[test]
    fn set_retries_and_reset_card() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]);
        assert_eq!(sw, Sw::OK);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x06).unwrap(), &[5, 5]);
        // Reset requires both references blocked.
        let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
        assert_eq!(sw, Sw::INCORRECT_PARAMS);
        let wrong = [0x39u8; 8];
        for _ in 0..5 {
            let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
        }
        let mut bad_unblock = wrong.to_vec();
        bad_unblock.extend_from_slice(&wrong);
        for _ in 0..4 {
            let _ = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &bad_unblock);
        }
        let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
        assert_eq!(sw, Sw::OK);
        // Factory state: default PIN verifies, the generated key is gone.
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
    }

    #[test]
    fn management_gates() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let scalar = [0x11u8; 32];
        let mut imp = vec![0x06, 32];
        imp.extend_from_slice(&scalar);
        let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        let mut setkey = vec![ALGO_AES192, 0x9B, 24];
        setkey.extend_from_slice(&DEFAULT_MGM);
        let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &setkey);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x82, 0x9A, &[]);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        // X25519 generation is rejected, not silently OK.
        auth_mgm(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_X25519),
        );
        assert_eq!(sw, WRONG_DATA);
        // Unknown INS.
        let (sw, _) = run(&mut app, &mut fs, 0x01, 0, 0, &[]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    }

    #[test]
    fn keys_at_rest_are_sealed() {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let scalar = [0x11u8; 32];
        let mut imp = vec![0x06, 32];
        imp.extend_from_slice(&scalar);
        let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
        assert_eq!(sw, Sw::OK);
        // The raw file must not contain the scalar (GCM-sealed).
        let mut blob = [0u8; 300];
        let n = fs.read(key_fid(0x9D), &mut blob).unwrap();
        assert!(n > 32);
        assert!(!blob[..n].windows(32).any(|w| w == scalar));
    }

    #[test]
    fn kbase_migration_reseals_slots_and_pin_falls_back() {
        const OTP: [u8; 32] = [0x44; 32];
        // Provision under a pre-OTP device: defaults + a generated 9A key.
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let (sw, resp) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
        let point = ec_point_of(&resp);

        // The boot pass re-seals the key slots; a second run is a no-op.
        let dev_new = Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: Some(&OTP),
        };
        migrate_kbase(&dev_new, &mut fs, &mut TestRng(9));
        migrate_kbase(&dev_new, &mut fs, &mut TestRng(11));

        // An OTP-build applet on the migrated state: the sealed management key
        // authenticates, the default PIN verifies via the fallback (and once
        // more directly against the re-stored verifier), and slot 9A signs with
        // the SAME key it had before the migration.
        let mut app2 = PivApplet::new(SERIAL, HASH, Some(OTP), &rng, &pres);
        select(&mut app2, &mut fs);
        auth_mgm(&mut app2, &mut fs);
        verify_pin(&mut app2, &mut fs);
        verify_pin(&mut app2, &mut fs);
        let digest: [u8; 32] = sha2::Sha256::digest(b"kbase migration").into();
        let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
        msg.extend_from_slice(&digest);
        let (sw, sig) = run(
            &mut app2,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            0x9A,
            &msg,
        );
        assert_eq!(sw, Sw::OK);
        let dyn_auth = find_tag(&sig, 0x7C).unwrap();
        let der = find_tag(dyn_auth, 0x82).unwrap().to_vec();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        let psig = p256::ecdsa::Signature::from_der(&der).unwrap();
        vk.verify_prehash(&digest, &psig).unwrap();

        // A pre-OTP applet no longer accepts the migrated PIN verifier.
        let mut app3 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        select(&mut app3, &mut fs);
        let (sw, _) = run(&mut app3, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
        assert_eq!(sw, Sw::new(0x63, 0xC2));
    }
}
