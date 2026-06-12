// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Rescue applet — the recovery / provisioning CCID interface under its own AID:
//! KEYDEV_SIGN 0x10 (device attestation), WRITE 0x1C (phy record, RTC time), READ
//! 0x1E (phy / flash stats / secure-boot status / time / anti-rollback state),
//! REBOOT 0x1F, OTP_LOCK 0x1B (one-way fuse writes: page-58 lock, rollback-required).

#![cfg_attr(not(test), no_std)]

pub mod keydev;
pub mod otp_lock;
pub mod phy;
pub mod rollback;

use core::cell::RefCell;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Rescue applet AID.
pub const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

// SELECT response identity: MCU, product, SDK version.
const MCU_RP2350: u8 = 1;
const PRODUCT_FIDO: u8 = 2;
const SDK_VERSION_MAJOR: u8 = 8;
const SDK_VERSION_MINOR: u8 = 6;

const INS_KEYDEV_SIGN: u8 = 0x10;
const INS_OTP_LOCK: u8 = 0x1B;
const INS_WRITE: u8 = 0x1C;
const INS_READ: u8 = 0x1E;
const INS_REBOOT_BOOTSEL: u8 = 0x1F;

/// OTP_LOCK payload guard: the irreversible page-58 lock fires only for this
/// exact data, so a stray or fuzzed APDU on INS 0x1B can never trigger it.
const OTP_LOCK_MAGIC: &[u8] = b"LOCK58";

/// OTP_LOCK P1=0x48 payload guard, same idea: the irreversible
/// ROLLBACK_REQUIRED fuse fires only for this exact data.
const ROLLBACK_MAGIC: &[u8] = b"ROLLBK";

/// READ P1=0x03 result.
pub struct SecureBootStatus {
    pub enabled: bool,
    pub locked: bool,
    /// Valid boot-key slot index, 0xFF when none.
    pub bootkey: u8,
}

/// Firmware-side services the applet needs: OTP secure-boot status (read-only),
/// the session RTC, and the deferred reboot (executed by the worker after the
/// response has flushed).
pub trait Platform {
    fn secure_boot_status(&self) -> SecureBootStatus;
    /// Seconds since the epoch; `None` until set this power cycle (the RTC is
    /// not battery-backed).
    fn now(&self) -> Option<u32>;
    fn set_time(&mut self, epoch: u32);
    fn request_reboot(&mut self, bootsel: bool);
    /// Raw 24-bit value of PAGE58_LOCK1; `None` on a read error. Drives the
    /// idempotency / refuse-foreign decision in [`otp_lock`].
    fn read_page58_lock_raw(&self) -> Option<u32>;
    /// Burn the page-58 access lock ([`otp_lock::PAGE58_LOCK_VALUE`] into
    /// [`otp_lock::PAGE58_LOCK1_ROW`]). The implementation fixes both the row
    /// and the value, so a caller can never redirect this write. IRREVERSIBLE;
    /// returns whether it succeeded.
    fn lock_page58(&mut self) -> bool;
    /// Raw RBIT-3 copies of the anti-rollback rows ([`rollback`]); `None` on
    /// any read error. Drives the idempotency decision and the READ report.
    fn read_rollback_raw(&self) -> Option<rollback::RollbackRaw>;
    /// Burn [`rollback::ROLLBACK_REQUIRED_BIT`] into every BOOT_FLAGS0 copy.
    /// The implementation fixes both the rows and the bit, so a caller can
    /// never redirect this write. IRREVERSIBLE; returns whether it succeeded.
    fn set_rollback_required(&mut self) -> bool;
}

pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

pub struct RescueApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned.
    otp_key: Option<[u8; 32]>,
    /// The OTP DEVK: the keydev secp256k1 scalar itself.
    devk: Option<[u8; 32]>,
    rng: &'a RefCell<dyn Rng>,
    platform: &'a RefCell<dyn Platform>,
    /// FLASH INFO `total`: the KV partition byte size.
    kv_total: u32,
    /// FLASH INFO `size`: the flash chip byte size.
    flash_size: u32,
}

impl<'a> RescueApplet<'a> {
    #[allow(clippy::too_many_arguments)] // boot-time wiring, mirrors CcidApplets::new
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        devk: Option<[u8; 32]>,
        rng: &'a RefCell<dyn Rng>,
        platform: &'a RefCell<dyn Platform>,
        kv_total: u32,
        flash_size: u32,
    ) -> Self {
        Self {
            serial_id,
            serial_hash,
            otp_key,
            devk,
            rng,
            platform,
            kv_total,
            flash_size,
        }
    }

    fn device(&self) -> Device<'_> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        }
    }

    fn keydev_sign<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.p1 {
            0x01 => {
                if apdu.nc != 32 {
                    return Sw::WRONG_LENGTH;
                }
                let mut rng = self.rng.borrow_mut();
                let Some(key) =
                    keydev::load_or_generate(&self.device(), self.devk.as_ref(), fs, &mut *rng)
                else {
                    return Sw::EXEC_ERROR;
                };
                let mut digest = [0u8; 32];
                digest.copy_from_slice(apdu.data);
                match keydev::sign_digest(&key, &digest) {
                    Some(sig) => {
                        res.extend(&sig);
                        Sw::OK
                    }
                    None => Sw::EXEC_ERROR,
                }
            }
            0x02 => {
                if apdu.nc != 0 {
                    return Sw::WRONG_LENGTH;
                }
                let mut rng = self.rng.borrow_mut();
                let Some(key) =
                    keydev::load_or_generate(&self.device(), self.devk.as_ref(), fs, &mut *rng)
                else {
                    return Sw::EXEC_ERROR;
                };
                res.extend(&keydev::public_uncompressed(&key));
                Sw::OK
            }
            0x03 => {
                if apdu.nc == 0 {
                    return Sw::WRONG_LENGTH;
                }
                if fs.put(keydev::EF_DEVCERT, apdu.data).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                Sw::OK
            }
            _ => Sw::INCORRECT_P1P2,
        }
    }

    fn write<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.nc < 2 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => {
                let parsed = phy::PhyData::parse(apdu.data);
                if phy::save(fs, &parsed).is_err() {
                    return Sw::EXEC_ERROR;
                }
                Sw::OK
            }
            0x02 => {
                let epoch = match apdu.p2 {
                    0x01 => {
                        if apdu.nc != 8 {
                            return Sw::WRONG_LENGTH;
                        }
                        let d = apdu.data;
                        let year = u16::from_be_bytes([d[0], d[1]]) as i64;
                        // d[4] is tm_wday — ignored on set, like mktime.
                        match epoch_from_civil(year, d[2], d[3], d[5], d[6], d[7]) {
                            Some(t) => t,
                            None => return Sw::DATA_INVALID,
                        }
                    }
                    0x02 => {
                        if apdu.nc != 4 {
                            return Sw::WRONG_LENGTH;
                        }
                        u32::from_be_bytes([apdu.data[0], apdu.data[1], apdu.data[2], apdu.data[3]])
                    }
                    _ => return Sw::INCORRECT_P1P2,
                };
                self.platform.borrow_mut().set_time(epoch);
                Sw::OK
            }
            // An unknown P1 is a no-op OK.
            _ => Sw::OK,
        }
    }

    fn read<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => {
                // A never-written phy serializes to just the zeroed OPTS TLV.
                let data = phy::load(fs).unwrap_or_default();
                let mut buf = [0u8; phy::PHY_MAX_SIZE];
                match data.serialize(&mut buf) {
                    Some(n) => {
                        res.extend(&buf[..n]);
                        Sw::OK
                    }
                    None => Sw::EXEC_ERROR,
                }
            }
            0x02 => {
                let (nfiles, used) = fs_usage(fs);
                let free = self.kv_total.saturating_sub(used);
                res.extend(&free.to_be_bytes());
                res.extend(&used.to_be_bytes());
                res.extend(&self.kv_total.to_be_bytes());
                res.extend(&nfiles.to_be_bytes());
                res.extend(&self.flash_size.to_be_bytes());
                Sw::OK
            }
            0x03 => {
                let st = self.platform.borrow().secure_boot_status();
                res.extend(&[st.enabled as u8, st.locked as u8, st.bootkey]);
                Sw::OK
            }
            0x04 => {
                if apdu.p2 != 0x01 && apdu.p2 != 0x02 {
                    return Sw::INCORRECT_P1P2;
                }
                let Some(t) = self.platform.borrow().now() else {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                };
                if apdu.p2 == 0x01 {
                    let c = civil_from_epoch(t);
                    res.extend(&c.year.to_be_bytes());
                    res.extend(&[c.mon0, c.mday, c.wday, c.hour, c.min, c.sec]);
                } else {
                    res.extend(&t.to_be_bytes());
                }
                Sw::OK
            }
            // 0x05 (trust digest) is deliberately not implemented.
            0x06 => {
                let Some(raw) = self.platform.borrow().read_rollback_raw() else {
                    return Sw::EXEC_ERROR;
                };
                let required = rollback::required(rollback::majority(raw.flags0));
                let version = rollback::version_count(
                    rollback::majority(raw.version0),
                    rollback::majority(raw.version1),
                );
                res.extend(&[required as u8, version, rollback::VERSION_CAPACITY]);
                Sw::OK
            }
            _ => Sw::INCORRECT_P1P2,
        }
    }

    fn reboot(&mut self, apdu: &Apdu) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => self.platform.borrow_mut().request_reboot(true),
            0x00 => self.platform.borrow_mut().request_reboot(false),
            _ => return Sw::INCORRECT_P1P2,
        }
        Sw::OK
    }

    /// INS 0x1B: the one-way OTP writes only secure firmware can perform, one
    /// per P1 (= the OTP row being targeted), each double-keyed by its own
    /// magic payload so a stray or fuzzed APDU can never burn a fuse.
    fn otp_lock(&mut self, apdu: &Apdu) -> Sw {
        if apdu.p2 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        match apdu.p1 {
            0x58 => self.lock_page58(apdu),
            0x48 => self.rollback_require(apdu),
            _ => Sw::INCORRECT_P1P2,
        }
    }

    /// Apply the permanent page-58 access lock from secure firmware — host
    /// tooling cannot (the lock row lives in bootloader-read-only OTP page 63).
    /// IRREVERSIBLE, so it is triply guarded: P1=0x58 (the page), the
    /// [`OTP_LOCK_MAGIC`] payload, and a provisioned MKEK (locking a blank
    /// page would only hide nothing while blinding BOOTSEL). Idempotent: a row
    /// already holding our value returns OK; any other non-blank value is
    /// refused rather than clobbered. See [`otp_lock`].
    fn lock_page58(&mut self, apdu: &Apdu) -> Sw {
        if apdu.data != OTP_LOCK_MAGIC {
            return Sw::DATA_INVALID;
        }
        if self.otp_key.is_none() {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(cur) = self.platform.borrow().read_page58_lock_raw() else {
            return Sw::EXEC_ERROR;
        };
        match otp_lock::lock_decision(cur) {
            otp_lock::LockDecision::AlreadyLocked => Sw::OK,
            otp_lock::LockDecision::Unexpected => Sw::CONDITIONS_NOT_SATISFIED,
            otp_lock::LockDecision::Write => {
                if !self.platform.borrow_mut().lock_page58() {
                    return Sw::EXEC_ERROR;
                }
                // Confirm the fuse took with a raw read-back.
                match self.platform.borrow().read_page58_lock_raw() {
                    Some(otp_lock::PAGE58_LOCK_VALUE) => Sw::OK,
                    _ => Sw::EXEC_ERROR,
                }
            }
        }
    }

    /// Fuse BOOT_FLAGS0.ROLLBACK_REQUIRED from secure firmware — on a board
    /// whose fuse pages are already bootloader-read-only (`rsk secure-boot
    /// lock`), host tooling cannot. IRREVERSIBLE, so it is triply guarded:
    /// P1=0x48 (the row), the [`ROLLBACK_MAGIC`] payload, and secure boot
    /// actually enabled — without enforcement the bit does nothing on this
    /// board, so burning it would be pointless fuse damage; with it, the
    /// command can only ever run from an image that itself passed the rollback
    /// check, which is exactly the safe ordering. Idempotent: already-fused
    /// (by 2-of-3 majority) returns OK without another write. See [`rollback`].
    fn rollback_require(&mut self, apdu: &Apdu) -> Sw {
        if apdu.data != ROLLBACK_MAGIC {
            return Sw::DATA_INVALID;
        }
        if !self.platform.borrow().secure_boot_status().enabled {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(raw) = self.platform.borrow().read_rollback_raw() else {
            return Sw::EXEC_ERROR;
        };
        if rollback::required(rollback::majority(raw.flags0)) {
            return Sw::OK;
        }
        if !self.platform.borrow_mut().set_rollback_required() {
            return Sw::EXEC_ERROR;
        }
        // Confirm the fuse took with a raw read-back of all three copies.
        match self.platform.borrow().read_rollback_raw() {
            Some(r) if rollback::required(rollback::majority(r.flags0)) => Sw::OK,
            _ => Sw::EXEC_ERROR,
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for RescueApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        RESCUE_AID
    }

    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        res.extend(&[
            MCU_RP2350,
            PRODUCT_FIDO,
            SDK_VERSION_MAJOR,
            SDK_VERSION_MINOR,
        ]);
        res.extend(&self.serial_id);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x80 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_KEYDEV_SIGN => self.keydev_sign(apdu, fs, res),
            INS_OTP_LOCK => self.otp_lock(apdu),
            INS_WRITE => self.write(apdu, fs),
            INS_READ => self.read(apdu, fs, res),
            INS_REBOOT_BOOTSEL => self.reboot(apdu),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// File count + summed payload bytes for FLASH INFO. Sizes are summed for the
/// first 512 files; the count is always exact.
fn fs_usage<S: Storage>(fs: &mut Fs<S>) -> (u32, u32) {
    let mut fids = [0u16; 512];
    let mut nfiles = 0u32;
    fs.for_each_key(&mut |fid| {
        if (nfiles as usize) < fids.len() {
            fids[nfiles as usize] = fid;
        }
        nfiles += 1;
    });
    let mut used = 0u32;
    for &fid in &fids[..(nfiles as usize).min(fids.len())] {
        used += fs.size(fid).unwrap_or(0) as u32;
    }
    (nfiles, used)
}

struct Civil {
    year: u16,
    mon0: u8,
    mday: u8,
    /// 0 = Sunday, like `tm_wday`.
    wday: u8,
    hour: u8,
    min: u8,
    sec: u8,
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Wire calendar (full year, 0-based month like `tm_mon`) to a u32 epoch.
fn epoch_from_civil(year: i64, mon0: u8, mday: u8, hour: u8, min: u8, sec: u8) -> Option<u32> {
    if mon0 > 11 || mday == 0 || mday > 31 || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, mon0 as u32 + 1, mday as u32);
    let secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    u32::try_from(secs).ok()
}

fn civil_from_epoch(t: u32) -> Civil {
    let days = (t / 86400) as i64;
    let rem = t % 86400;
    // Inverse of days_from_civil.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    Civil {
        year: year as u16,
        mon0: (m - 1) as u8,
        mday: d as u8,
        wday: ((days + 4).rem_euclid(7)) as u8,
        hour: (rem / 3600) as u8,
        min: (rem % 3600 / 60) as u8,
        sec: (rem % 60) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    struct LcgRng(u64);
    impl Rng for LcgRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    struct FakePlatform {
        time: Option<u32>,
        reboots: Vec<bool>,
        status: (bool, bool, u8),
        /// Simulated PAGE58_LOCK1 raw value; `None` models a read error.
        lock_raw: Option<u32>,
        lock_writes: u32,
        /// Simulated anti-rollback rows; `None` models a read error.
        rollback_raw: Option<rollback::RollbackRaw>,
        rollback_writes: u32,
    }
    impl Default for FakePlatform {
        fn default() -> Self {
            FakePlatform {
                time: None,
                reboots: Vec::new(),
                status: (false, false, 0xFF),
                lock_raw: Some(0),
                lock_writes: 0,
                rollback_raw: Some(rollback::RollbackRaw {
                    flags0: [0; 3],
                    version0: [0; 3],
                    version1: [0; 3],
                }),
                rollback_writes: 0,
            }
        }
    }
    impl Platform for FakePlatform {
        fn secure_boot_status(&self) -> SecureBootStatus {
            SecureBootStatus {
                enabled: self.status.0,
                locked: self.status.1,
                bootkey: self.status.2,
            }
        }
        fn now(&self) -> Option<u32> {
            self.time
        }
        fn set_time(&mut self, epoch: u32) {
            self.time = Some(epoch);
        }
        fn request_reboot(&mut self, bootsel: bool) {
            self.reboots.push(bootsel);
        }
        fn read_page58_lock_raw(&self) -> Option<u32> {
            self.lock_raw
        }
        fn lock_page58(&mut self) -> bool {
            // OTP bits only go 0→1; model the fuse burning to our value.
            self.lock_writes += 1;
            self.lock_raw = Some(otp_lock::PAGE58_LOCK_VALUE);
            true
        }
        fn read_rollback_raw(&self) -> Option<rollback::RollbackRaw> {
            self.rollback_raw
        }
        fn set_rollback_required(&mut self) -> bool {
            // OR the bit into every copy, like the firmware burn does.
            self.rollback_writes += 1;
            if let Some(raw) = self.rollback_raw.as_mut() {
                for row in raw.flags0.iter_mut() {
                    *row |= rollback::ROLLBACK_REQUIRED_BIT;
                }
            }
            true
        }
    }

    const SERIAL_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0xA5; 32];
    const KV_TOTAL: u32 = 64 * 1024;
    const FLASH_SIZE: u32 = 4 * 1024 * 1024;

    fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut a = vec![cla, ins, p1, p2];
        if !data.is_empty() {
            a.push(data.len() as u8);
            a.extend_from_slice(data);
        }
        a.push(0); // Le
        a
    }

    fn run(app: &mut RescueApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
        let mut buf = [0u8; 512];
        let parsed = Apdu::parse(raw).unwrap();
        let mut res = ResBuf::new(&mut buf);
        let sw = app.process(&parsed, fs, &mut res);
        (sw, res.as_slice().to_vec())
    }

    #[test]
    fn select_reports_identity() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut buf = [0u8; 64];
        let mut res = ResBuf::new(&mut buf);
        let sw = Applet::<Fs<RamStorage>>::select(&mut app, false, &mut fs, &mut res);
        assert_eq!(sw, Sw::OK);
        let mut want = vec![1u8, 2, 8, 6]; // RP2350, FIDO product, SDK 8.6
        want.extend_from_slice(&SERIAL_ID);
        assert_eq!(res.as_slice(), &want[..]);
    }

    #[test]
    fn cla_is_checked() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x00, INS_READ, 0x03, 0, &[]));
        assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
    }

    fn lock_app<'a>(
        rng: &'a RefCell<LcgRng>,
        platform: &'a RefCell<FakePlatform>,
        otp_key: Option<[u8; 32]>,
    ) -> RescueApplet<'a> {
        RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            otp_key,
            None,
            rng,
            platform,
            KV_TOTAL,
            FLASH_SIZE,
        )
    }

    fn lock_apdu() -> Vec<u8> {
        apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, OTP_LOCK_MAGIC)
    }

    #[test]
    fn otp_lock_writes_once_then_idempotent() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default()); // lock_raw = Some(0)
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);

        let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
        assert_eq!(sw, Sw::OK);
        assert_eq!(platform.borrow().lock_writes, 1);
        assert_eq!(
            platform.borrow().lock_raw,
            Some(otp_lock::PAGE58_LOCK_VALUE)
        );

        // A second call finds the row already locked: OK, no further fuse write.
        let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
        assert_eq!(sw, Sw::OK);
        assert_eq!(platform.borrow().lock_writes, 1, "must not re-burn");
    }

    #[test]
    fn otp_lock_refused_without_provisioned_keys() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = lock_app(&rng, &platform, None); // no MKEK
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
        assert_eq!(platform.borrow().lock_writes, 0);
    }

    #[test]
    fn otp_lock_rejects_bad_guards() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);

        // wrong P1 (not the page number)
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x00, 0x00, OTP_LOCK_MAGIC),
        );
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        // wrong magic payload
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, b"nope"),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
        // wrong CLA never reaches the handler
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x00, INS_OTP_LOCK, 0x58, 0x00, OTP_LOCK_MAGIC),
        );
        assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);

        assert_eq!(platform.borrow().lock_writes, 0, "no guard path may burn");
    }

    #[test]
    fn otp_lock_refuses_foreign_lock_value() {
        let rng = RefCell::new(LcgRng(7));
        // a different, pre-existing lock config
        let platform = RefCell::new(FakePlatform {
            lock_raw: Some(0x14_14_14),
            ..Default::default()
        });
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
        assert_eq!(
            platform.borrow().lock_writes,
            0,
            "never clobber a non-blank row"
        );
    }

    #[test]
    fn otp_lock_read_error_is_exec_error() {
        let rng = RefCell::new(LcgRng(7));
        // model a read failure
        let platform = RefCell::new(FakePlatform {
            lock_raw: None,
            ..Default::default()
        });
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
        assert_eq!(sw, Sw::EXEC_ERROR);
        assert_eq!(platform.borrow().lock_writes, 0);
    }

    fn rollback_apdu() -> Vec<u8> {
        apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, ROLLBACK_MAGIC)
    }

    /// A platform with secure boot enabled (the rollback-require gate).
    fn secure_platform() -> FakePlatform {
        FakePlatform {
            status: (true, true, 0),
            ..Default::default()
        }
    }

    #[test]
    fn rollback_require_burns_once_then_idempotent() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(secure_platform());
        let mut app = lock_app(&rng, &platform, None); // no MKEK needed for this one
        let mut fs = Fs::new(RamStorage::new(), &[]);

        let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
        assert_eq!(sw, Sw::OK);
        assert_eq!(platform.borrow().rollback_writes, 1);
        let flags0 = platform.borrow().rollback_raw.unwrap().flags0;
        assert!(
            flags0
                .iter()
                .all(|r| r & rollback::ROLLBACK_REQUIRED_BIT != 0)
        );

        // A second call finds the bit already fused: OK, no further write.
        let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
        assert_eq!(sw, Sw::OK);
        assert_eq!(platform.borrow().rollback_writes, 1, "must not re-burn");
    }

    #[test]
    fn rollback_require_needs_secure_boot() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default()); // secure boot off
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
        assert_eq!(platform.borrow().rollback_writes, 0);
    }

    #[test]
    fn rollback_require_rejects_bad_guards() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(secure_platform());
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);

        // wrong magic (including the *other* P1's magic)
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, b"nope"),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, OTP_LOCK_MAGIC),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
        // magics must not cross over to the page-58 arm either
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, ROLLBACK_MAGIC),
        );
        assert_eq!(sw, Sw::DATA_INVALID);
        // nonzero P2
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_OTP_LOCK, 0x48, 0x01, ROLLBACK_MAGIC),
        );
        assert_eq!(sw, Sw::INCORRECT_P1P2);

        assert_eq!(
            platform.borrow().rollback_writes,
            0,
            "no guard path may burn"
        );
        assert_eq!(platform.borrow().lock_writes, 0);
    }

    #[test]
    fn rollback_require_read_error_is_exec_error() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform {
            rollback_raw: None,
            ..secure_platform()
        });
        let mut app = lock_app(&rng, &platform, Some([0x11; 32]));
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
        assert_eq!(sw, Sw::EXEC_ERROR);
        assert_eq!(platform.borrow().rollback_writes, 0);
    }

    #[test]
    fn rollback_state_read() {
        let rng = RefCell::new(LcgRng(7));
        // Two of three flags copies fused (majority: required), thermometer at
        // 3 + 1 across the two words — incl. one sparse single-copy bit that
        // must NOT count (majority zero).
        let platform = RefCell::new(FakePlatform {
            rollback_raw: Some(rollback::RollbackRaw {
                flags0: [
                    rollback::ROLLBACK_REQUIRED_BIT,
                    rollback::ROLLBACK_REQUIRED_BIT,
                    0,
                ],
                version0: [0b111, 0b111, 0b011],
                version1: [0b11, 0b01, 0b01],
            }),
            ..Default::default()
        });
        let mut app = lock_app(&rng, &platform, None);
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, vec![1, 4, rollback::VERSION_CAPACITY]);

        // Blank board: not required, version 0.
        platform.borrow_mut().rollback_raw = Some(rollback::RollbackRaw {
            flags0: [0; 3],
            version0: [0; 3],
            version1: [0; 3],
        });
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, vec![0, 0, rollback::VERSION_CAPACITY]);

        // Read error.
        platform.borrow_mut().rollback_raw = None;
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
        assert_eq!(sw, Sw::EXEC_ERROR);
    }

    #[test]
    fn keydev_sign_verifies_and_key_persists() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);

        let (sw, pubkey) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x02, 0, &[]),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04);

        let digest = [0x42u8; 32];
        let (sw, sig) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x01, 0, &digest),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(sig.len(), 64);

        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let sig = k256::ecdsa::Signature::from_slice(&sig).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();

        // Same key on re-load (sealed in EF_DEVCERT_KEY, not regenerated).
        let (_, pubkey2) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x02, 0, &[]),
        );
        assert_eq!(pubkey, pubkey2);

        // Wrong digest length.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x01, 0, &[0; 16]),
        );
        assert_eq!(sw, Sw::WRONG_LENGTH);
    }

    #[test]
    fn keydev_cert_upload() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let cert = [0x30u8, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x03, 0, &cert),
        );
        assert_eq!(sw, Sw::OK);
        let mut buf = [0u8; 16];
        assert_eq!(fs.read(keydev::EF_DEVCERT, &mut buf), Some(cert.len()));
        assert_eq!(&buf[..cert.len()], &cert);
        // Empty upload is rejected.
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_KEYDEV_SIGN, 0x03, 0, &[]),
        );
        assert_eq!(sw, Sw::WRONG_LENGTH);
    }

    #[test]
    fn phy_write_read_roundtrip() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);

        // Virgin device: READ phy returns just the zero OPTS TLV.
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x01, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, vec![0x06, 0x02, 0x00, 0x00]);

        // Write VIDPID + brightness; read back includes the ITF_ALL default.
        let blob = [0x00, 4, 0x10, 0x50, 0x04, 0x07, 0x05, 1, 99];
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x01, 0, &blob));
        assert_eq!(sw, Sw::OK);
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x01, 0, &[]));
        assert_eq!(sw, Sw::OK);
        let phy = phy::PhyData::parse(&body);
        assert_eq!(phy.vid_pid, Some((0x1050, 0x0407)));
        assert_eq!(phy.led_brightness, Some(99));
        assert_eq!(phy.enabled_usb_itf, Some(phy::USB_ITF_ALL));
    }

    #[test]
    fn flash_info_layout() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.put(0x1111, &[0u8; 10]).unwrap();
        fs.put(0x2222, &[0u8; 6]).unwrap();

        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x02, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body.len(), 20);
        let w = |i: usize| u32::from_be_bytes(body[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(w(0), KV_TOTAL - 16); // free
        assert_eq!(w(1), 16); // used
        assert_eq!(w(2), KV_TOTAL);
        assert_eq!(w(3), 2); // nfiles
        assert_eq!(w(4), FLASH_SIZE);
    }

    #[test]
    fn secure_boot_status() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform {
            status: (true, false, 2),
            ..Default::default()
        });
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x03, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, vec![1, 0, 2]);
    }

    #[test]
    fn time_set_and_get_both_forms() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);

        // Before set: 6985.
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

        // Set 2026-06-11 00:00:00 UTC as a unix stamp; read back both forms.
        let t: u32 = 1781136000;
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_WRITE, 0x02, 0x02, &t.to_be_bytes()),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, t.to_be_bytes());
        let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x01, &[]));
        assert_eq!(sw, Sw::OK);
        // year, mon0=5 (June), mday=11, wday=4 (Thursday), 00:00:00.
        assert_eq!(body, vec![0x07, 0xEA, 5, 11, 4, 0, 0, 0]);

        // Set via the calendar form; get the same stamp back.
        let cal = [0x07, 0xEA, 5, 11, 0 /* wday ignored */, 12, 34, 56];
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x02, 0x01, &cal));
        assert_eq!(sw, Sw::OK);
        let (_, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
        assert_eq!(body, (t + 12 * 3600 + 34 * 60 + 56).to_be_bytes());

        // Invalid month.
        let bad = [0x07, 0xEA, 12, 11, 0, 0, 0, 0];
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x02, 0x01, &bad));
        assert_eq!(sw, Sw::DATA_INVALID);
    }

    #[test]
    fn reboot_requests() {
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);

        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_REBOOT_BOOTSEL, 0x01, 0, &[]),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_REBOOT_BOOTSEL, 0x00, 0, &[]),
        );
        assert_eq!(sw, Sw::OK);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_REBOOT_BOOTSEL, 0x07, 0, &[]),
        );
        assert_eq!(sw, Sw::INCORRECT_P1P2);
        assert_eq!(platform.borrow().reboots, vec![true, false]);
    }

    #[test]
    fn secure_ins_is_not_supported() {
        // 0x1D (enable secure boot) is deliberately unimplemented.
        let rng = RefCell::new(LcgRng(7));
        let platform = RefCell::new(FakePlatform::default());
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            KV_TOTAL,
            FLASH_SIZE,
        );
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, 0x1D, 0x00, 0, &[]));
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
        assert!(platform.borrow().reboots.is_empty());
    }
}
