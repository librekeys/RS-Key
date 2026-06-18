// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! TERMINATE DF (0xE6): factory-reset the OpenPGP applet. The `Fs` is shared
//! with the FIDO applet, so only OpenPGP-owned files are deleted (a terminate
//! must not wipe FIDO state, and vice versa) before re-seeding via [`scan_files`].

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Sw};

use crate::Rng;
use crate::consts::*;
use crate::init::scan_files;

/// Whether `fid` is an OpenPGP-owned flash file. The OpenPGP data-object tag space
/// (`0x00xx`/`0x01xx`/`0x5fxx`/`0x7fxx`) contains no FIDO files, so those are tested
/// as ranges; the internal EFs sit in the `0x10xx`/`0x1fxx` region that *interleaves*
/// with FIDO (FIDO `EF_PIN` 0x1080 falls between OpenPGP PW1 0x1081 and FIDO 0x1090),
/// so those are an explicit set — never a range. Verified disjoint from `is_fido_fid`.
pub fn is_openpgp_fid(fid: u16) -> bool {
    // Private-key + PW-DEK slots are `KeyFid`s (sealed secrets), so they can't be
    // `u16` match patterns — compare their raw FIDs explicitly.
    if fid == EF_PK_SIG.get()
        || fid == EF_PK_DEC.get()
        || fid == EF_PK_AUT.get()
        || fid == EF_DEK_PW1.get()
        || fid == EF_DEK_RC.get()
        || fid == EF_DEK_PW3.get()
    {
        return true;
    }
    (0x0001..0x0200).contains(&fid)
        || (0x5f00..0x6000).contains(&fid)
        || (0x7f00..0x8000).contains(&fid)
        || matches!(
            fid,
            EF_PW1
                | EF_RC
                | EF_PW3
                | EF_ALGO_PRIV1
                | EF_ALGO_PRIV2
                | EF_ALGO_PRIV3
                | EF_PW_PRIV
                | EF_PW_RETRIES
                | EF_PB_SIG
                | EF_PB_DEC
                | EF_PB_AUT
                | EF_DEK
                | EF_DEK_PWPIV
                | EF_CH_1
                | EF_CH_2
                | EF_CH_3
        )
}

/// Factory-reset the OpenPGP applet. Permitted only when the admin PIN (PW3) is
/// verified or already blocked (its retry counter has reached 0).
pub fn terminate_df<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    has_pw3: bool,
    apdu: &Apdu,
) -> Sw {
    if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
        return Sw::INCORRECT_P1P2;
    }
    let mut pw = [0u8; 7];
    let n = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) => n,
        None => return Sw::REFERENCE_NOT_FOUND,
    };
    // EF_PW_PRIV[6] is the live PW3 retry counter (`pin_wrong_retry` decrements it).
    if !has_pw3 && n > 6 && pw[6] > 0 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    if apdu.nc != 0 {
        return Sw::WRONG_LENGTH;
    }
    wipe_openpgp(fs);
    if scan_files(dev, fs, rng).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// Delete every live OpenPGP file. Batched because `for_each_key` cannot delete
/// mid-iteration; each round deletes ≥1 key, so it converges (mirrors the FIDO reset).
fn wipe_openpgp<S: Storage>(fs: &mut Fs<S>) {
    loop {
        let mut keys = [0u16; 64];
        let mut k = 0usize;
        fs.for_each_key(&mut |fid| {
            if is_openpgp_fid(fid) && k < keys.len() {
                keys[k] = fid;
                k += 1;
            }
        });
        if k == 0 {
            break;
        }
        for &fid in &keys[..k] {
            let _ = fs.delete(fid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    struct CountRng(u8);
    impl Rng for CountRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0x11; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn seeded() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        fs
    }

    fn apdu() -> Apdu<'static> {
        Apdu {
            cla: 0x00,
            ins: INS_TERMINATE_DF,
            p1: 0x00,
            p2: 0x00,
            nc: 0,
            ne: 0,
            data: &[],
        }
    }

    #[test]
    fn openpgp_fids_classified_disjoint_from_fido() {
        // OpenPGP internal EFs + a few DO tags.
        for fid in [
            EF_PW1,
            EF_PW3,
            EF_PK_SIG.get(),
            EF_DEK,
            EF_LOGIN_DATA,
            EF_FP,
            EF_SEX,
        ] {
            assert!(is_openpgp_fid(fid), "{fid:#06x} should be OpenPGP");
        }
        // FIDO FIDs (see rsk-fido `is_fido_fid`) must NOT be classified as OpenPGP.
        for fid in [
            0x1080u16, 0x1090, 0x1091, 0x1100, 0x1101, 0xC000, 0xCC00, 0xCF00, 0xD000,
        ] {
            assert!(!is_openpgp_fid(fid), "{fid:#06x} is FIDO, not OpenPGP");
        }
    }

    #[test]
    fn terminate_wipes_openpgp_and_reseeds() {
        let mut fs = seeded();
        // User data that a terminate must erase.
        fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
        fs.put(EF_LOGIN_DATA, b"alice").unwrap();
        // A FIDO file sharing the Fs must SURVIVE (0x1080 = FIDO EF_PIN).
        fs.put(0x1080, &[8, 4, 1, 0, 0]).unwrap();
        // PW3 verified → terminate permitted.
        assert_eq!(
            terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu()),
            Sw::OK
        );

        assert!(!fs.has_data(EF_PK_SIG.get()), "imported key must be wiped");
        assert!(!fs.has_data(EF_LOGIN_DATA), "login data must be wiped");
        assert!(
            fs.has_data(0x1080),
            "FIDO file must survive an OpenPGP terminate"
        );
        // Defaults re-seeded.
        assert!(fs.has_data(EF_DEK_PW1.get()));
        let mut pw = [0u8; 7];
        fs.read(EF_PW_PRIV, &mut pw);
        assert_eq!(pw[0], 0x01);
    }

    #[test]
    fn terminate_refused_without_pw3_while_unblocked() {
        let mut fs = seeded();
        // Default PW3 retry counter is 3 (> 0) and PW3 not verified → refused.
        assert_eq!(
            terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert!(fs.has_data(EF_DEK_PW1.get()), "nothing wiped on refusal");
    }

    #[test]
    fn terminate_allowed_without_pw3_when_admin_blocked() {
        let mut fs = seeded();
        // Drive the PW3 retry counter to 0 (admin PIN blocked).
        let mut pw = [0u8; 7];
        let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
        pw[6] = 0;
        fs.put(EF_PW_PRIV, &pw[..n]).unwrap();
        assert_eq!(
            terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
            Sw::OK
        );
    }

    #[test]
    fn terminate_rejects_p1p2_and_data() {
        let mut fs = seeded();
        let mut bad = apdu();
        bad.p1 = 0x01;
        assert_eq!(
            terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &bad),
            Sw::INCORRECT_P1P2
        );
        let data = [0u8; 2];
        let withdata = Apdu {
            nc: 2,
            data: &data,
            ..apdu()
        };
        assert_eq!(
            terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &withdata),
            Sw::WRONG_LENGTH
        );
    }
}
