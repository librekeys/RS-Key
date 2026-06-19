// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorReset`: wipe all FIDO flash state and the in-RAM PIN/UV
//! session, then regenerate the device seed / counter / attestation cert. A
//! physical touch gates the wipe; the spec's optional power-on window is not enforced.

use rsk_fs::Storage;

use crate::consts::{
    EF_AUTHTOKEN, EF_BACKUP_SEALED, EF_COUNTER, EF_CRED, EF_EA_ENABLED, EF_EE_DEV, EF_KEY_DEV,
    EF_KEY_DEV_ENC, EF_LARGEBLOB, EF_MINPINLEN, EF_PAUTHTOKEN, EF_PIN, EF_RP,
    MAX_RESIDENT_CREDENTIALS,
};
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::ensure_seed;
use crate::{Ctx, Rng};

/// `authenticatorReset`: factory-reset the FIDO applet. Replies with only the
/// status byte. Also the documented recovery from a soft lock with a lost lock
/// key: `EF_KEY_DEV_ENC` is wiped with everything else and a fresh seed is
/// generated (the old identity is gone — that is the design).
pub fn reset<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    // A factory reset requires a physical touch; both a timeout and a cancel
    // abort it before anything is wiped.
    if !ctx.check_user_presence() {
        return Err(CtapError::UserActionTimeout);
    }
    // Drop every FIDO file, then regenerate the seed. The flash `Fs` is shared
    // with the OpenPGP applet, so delete only live, FIDO-owned keys
    // ([`is_fido_fid`]) — a blind 0..256 EF_CRED/EF_RP sweep would write a
    // tombstone per absent slot, filling the partition and slowing the flash GC.
    loop {
        let mut keys = [0u16; 64];
        let mut n = 0usize;
        ctx.fs.for_each_key(&mut |fid| {
            if is_fido_fid(fid) && n < keys.len() {
                keys[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            break;
        }
        for &fid in &keys[..n] {
            let _ = ctx.fs.delete(fid);
        }
    }
    ctx.state.reset();
    ensure_seed(&ctx.dev, ctx.fs, ctx.rng).map_err(|_| CtapError::Other)?;
    // Privacy: fold the journal window into the epoch (per-event details are
    // scrubbed, aggregate history stays attested), then record the reset.
    journal::fold_and_scrub(ctx);
    journal::append(ctx, journal::EV_RESET, 0, &[]);
    Ok(0)
}

/// Whether `fid` is a FIDO-owned flash file. `authenticatorReset` deletes only
/// these, never the OpenPGP applet's files (0x1081-0x10d6 / 0x00xx / 0x5fxx /
/// 0x1f2x) or the vendor counter (0xCC01). FIDO and OpenPGP interleave in the
/// 0x10xx range (FIDO `EF_PIN` 0x1080 vs OpenPGP PW1 0x1081), so this is an
/// explicit set plus the resident-credential ranges, not a range test.
fn is_fido_fid(fid: u16) -> bool {
    // EF_KEY_DEV / EF_KEY_DEV_ENC are `KeyFid`s (sealed seed slots), so they
    // can't sit in the `u16` match arm — compare their raw FIDs explicitly.
    fid == EF_KEY_DEV.get()
        || fid == EF_KEY_DEV_ENC.get()
        || matches!(
            fid,
            EF_BACKUP_SEALED
                | EF_EE_DEV
                | EF_COUNTER
                | EF_PIN
                | EF_AUTHTOKEN
                | EF_PAUTHTOKEN
                | EF_MINPINLEN
                | EF_LARGEBLOB
                | EF_EA_ENABLED
        )
        || (EF_CRED..EF_CRED + MAX_RESIDENT_CREDENTIALS).contains(&fid)
        || (EF_RP..EF_RP + MAX_RESIDENT_CREDENTIALS).contains(&fid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FidoState;
    use crate::consts::{EF_CRED, EF_LARGEBLOB, EF_PIN};
    use crate::seed::{bump_sign_counter, get_sign_counter, load_keydev};
    use rsk_crypto::Device;
    use rsk_fs::Fs;
    use rsk_fs::storage::ram::RamStorage;

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    #[test]
    fn reset_wipes_state_and_regenerates() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        // Provisioned state: a PIN, a resident credential, an advanced counter,
        // and a non-default large blob.
        fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
        fs.put(EF_CRED, &[0u8; 100]).unwrap();
        fs.put(EF_LARGEBLOB, &[0xAB; 50]).unwrap();
        // An OpenPGP file (EF_PW3 = 0x1083) shares the Fs and must survive a FIDO
        // reset — it sits in the 0x10xx range right next to FIDO's own files.
        fs.put(0x1083, &[0xAB; 34]).unwrap();
        bump_sign_counter(&mut fs).unwrap();
        bump_sign_counter(&mut fs).unwrap();
        assert_eq!(get_sign_counter(&mut fs), 2);

        let mut state = FidoState::new();
        state.paut.permissions = 0x07;

        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            reset(&mut ctx).unwrap()
        };
        assert_eq!(n, 0);
        // Files wiped, counter reset, seed regenerated and PIN-free again.
        assert!(!fs.has_data(EF_PIN));
        assert!(!fs.has_data(EF_CRED));
        // The OpenPGP file is untouched by the FIDO reset.
        assert!(
            fs.has_data(0x1083),
            "OpenPGP files must survive a FIDO reset"
        );
        assert_eq!(get_sign_counter(&mut fs), 0);
        assert!(load_keydev(&dev(), &mut fs).is_some());
        // Large blob wiped and re-initialised to the CTAP2.1 default.
        let mut lb = [0u8; 64];
        let ln = fs.read(EF_LARGEBLOB, &mut lb).unwrap();
        assert_eq!(&lb[..ln], &crate::consts::LARGEBLOB_INITIAL);
        // Session state cleared.
        assert_eq!(state.paut.permissions, 0);
    }

    struct Fixed(crate::Presence);
    impl crate::UserPresence for Fixed {
        fn request(&mut self) -> crate::Presence {
            self.0
        }
    }

    #[test]
    fn reset_aborts_without_touch() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
        let mut state = FidoState::new();
        let r = {
            let mut presence = Fixed(crate::Presence::Timeout);
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            reset(&mut ctx)
        };
        assert_eq!(r, Err(CtapError::UserActionTimeout));
        // A declined touch wipes nothing.
        assert!(fs.has_data(EF_PIN));
    }
}
