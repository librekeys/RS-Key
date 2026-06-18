// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERAL AUTHENTICATE (INS 0x87): management-key mutual/single auth (3DES/AES
//! witness–challenge–response), slot private-key operations (raw RSA — blinded
//! with a CRT-fault check — and ECDSA over a host digest), and ECDH via tag
//! 0x85 (the operation `ykman calculate_secret` performs). Every private-key
//! operation enforces the key's stored touch policy ([`check_touch`]), requested
//! once per logical operation (mutual auth touches at the witness step only);
//! a witness mismatch fails closed; symmetric operations are 9B-only.

use rsa::BigUint;
use rsa::traits::PublicKeyParts;
use rsk_crypto::{
    Device, aes_ecb_decrypt_block, aes_ecb_encrypt_block, des3_decrypt_block, des3_encrypt_block,
};
use rsk_fs::{Fs, Storage};
use rsk_openpgp::keys::Curve;
use rsk_openpgp::{Presence, Rng, UserPresence};
use rsk_sdk::tlv::find_tag;
use rsk_sdk::{ResBuf, Sw};
use zeroize::Zeroize;

use crate::files::*;
use crate::seal;
use crate::x509;
use crate::{RngAdapter, Session, WRONG_DATA, ct_eq, dyn_auth_resp};

enum Dir {
    Encrypt,
    Decrypt,
}

/// Enforce the slot/management-key touch policy before a private-key operation.
/// `ALWAYS` and `CACHED` require a physical touch (CACHED is treated as ALWAYS —
/// with no wall clock the 15-second cache window cannot be honoured, so it errs
/// strict); a non-confirmation fails the operation. `NEVER`/`DEFAULT`/`AUTO`
/// pass through.
fn check_touch(policy: u8, presence: &mut dyn UserPresence) -> Result<(), Sw> {
    if matches!(policy, TOUCHPOLICY_ALWAYS | TOUCHPOLICY_CACHED) {
        match presence.request() {
            Presence::Confirmed => Ok(()),
            _ => Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
        }
    } else {
        Ok(())
    }
}

/// One ECB block under the management key; `data` is `chal_len` bytes.
fn mgm_crypt(algo: u8, key: &[u8], data: &mut [u8], dir: Dir) -> Result<(), Sw> {
    match algo {
        ALGO_3DES => {
            let key: &[u8; 24] = key.try_into().map_err(|_| Sw::MEMORY_FAILURE)?;
            let block: &mut [u8; 8] = data.try_into().map_err(|_| WRONG_DATA)?;
            match dir {
                Dir::Encrypt => des3_encrypt_block(key, block),
                Dir::Decrypt => des3_decrypt_block(key, block),
            }
            Ok(())
        }
        _ => {
            let block: &mut [u8; 16] = data.try_into().map_err(|_| WRONG_DATA)?;
            match dir {
                Dir::Encrypt => aes_ecb_encrypt_block(key, block),
                Dir::Decrypt => aes_ecb_decrypt_block(key, block),
            }
            .map_err(|_| Sw::MEMORY_FAILURE)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn general_authenticate<S: Storage>(
    sess: &mut Session,
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    algo: u8,
    key_ref: u8,
    data: &[u8],
    res: &mut ResBuf,
) -> Sw {
    if data.is_empty() {
        return Sw::WRONG_LENGTH;
    }
    if data[0] != 0x7C {
        return WRONG_DATA;
    }
    let Some(dyn_auth) = find_tag(data, 0x7C) else {
        return WRONG_DATA;
    };
    if dyn_auth.is_empty() {
        return WRONG_DATA;
    }

    // Management-key sanity (algo class + stored length).
    let mut mgm_key = [0u8; 32];
    let mut mgm_len = 0usize;
    if key_ref == SLOT_CARDMGM {
        if !matches!(algo, ALGO_3DES | ALGO_AES128 | ALGO_AES192 | ALGO_AES256) {
            return Sw::INCORRECT_P1P2;
        }
        mgm_len = match seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut mgm_key) {
            Ok(n) => n,
            Err(_) => return Sw::MEMORY_FAILURE,
        };
        let want = match algo {
            ALGO_AES128 => 16,
            ALGO_AES192 | ALGO_3DES => 24,
            _ => 32,
        };
        if mgm_len != want {
            mgm_key.zeroize();
            return Sw::INCORRECT_P1P2;
        }
    }

    let mut meta = [0u8; 8];
    let Some(_meta_len) = fs.meta_find(key_fid(key_ref).get(), &mut meta) else {
        mgm_key.zeroize();
        return Sw::REFERENCE_NOT_FOUND;
    };
    let mut pinpol = meta[1];
    if pinpol == PINPOLICY_DEFAULT {
        pinpol = if key_ref == SLOT_SIGNATURE {
            PINPOLICY_ALWAYS
        } else {
            PINPOLICY_ONCE
        };
    }
    if (pinpol == PINPOLICY_ALWAYS || pinpol == PINPOLICY_ONCE) && is_key(key_ref) && !sess.has_pin
    {
        mgm_key.zeroize();
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // Touch policy of the key being used (slot key, or 9B management key).
    let touch_policy = meta[2];

    let chal_len: usize = if algo == ALGO_3DES { 8 } else { 16 };
    let t80 = find_tag(dyn_auth, 0x80);
    let t81 = find_tag(dyn_auth, 0x81);
    let t82 = find_tag(dyn_auth, 0x82);
    let t85 = find_tag(dyn_auth, 0x85);

    let sw = (|| -> Result<(), Sw> {
        if let Some(w) = t80 {
            if w.is_empty() {
                // Mutual auth step 1: return the encrypted witness. The touch is
                // requested here (the start of the handshake) so step 2 needs no
                // second one.
                if key_ref != SLOT_CARDMGM {
                    return Err(Sw::INCORRECT_P1P2);
                }
                check_touch(touch_policy, presence)?;
                rng.fill(&mut sess.challenge[..chal_len]);
                let mut enc = [0u8; 16];
                enc[..chal_len].copy_from_slice(&sess.challenge[..chal_len]);
                mgm_crypt(
                    algo,
                    &mgm_key[..mgm_len],
                    &mut enc[..chal_len],
                    Dir::Encrypt,
                )?;
                sess.has_challenge = true;
                dyn_auth_resp(res, 0x80, &enc[..chal_len])?;
                return Ok(());
            }
            // Mutual auth step 2: host returns the decrypted witness + its own
            // challenge; verify, then answer with the encrypted host challenge.
            if key_ref != SLOT_CARDMGM {
                return Err(Sw::INCORRECT_P1P2);
            }
            if !sess.has_challenge {
                return Err(Sw::INCORRECT_PARAMS);
            }
            let host_chal = t81.filter(|c| !c.is_empty()).ok_or(Sw::INCORRECT_PARAMS)?;
            sess.has_challenge = false;
            if w.len() != chal_len || !ct_eq(w, &sess.challenge[..chal_len]) {
                return Err(Sw::DATA_INVALID);
            }
            sess.has_mgm = true;
            if host_chal.len() != chal_len {
                return Err(Sw::DATA_INVALID);
            }
            let mut enc = [0u8; 16];
            enc[..chal_len].copy_from_slice(host_chal);
            mgm_crypt(
                algo,
                &mgm_key[..mgm_len],
                &mut enc[..chal_len],
                Dir::Encrypt,
            )?;
            dyn_auth_resp(res, 0x82, &enc[..chal_len])?;
            return Ok(());
        }

        if let Some(c) = t81 {
            if c.is_empty() {
                // Single auth step 1: return a plaintext challenge.
                rng.fill(&mut sess.challenge[..chal_len]);
                sess.has_challenge = true;
                dyn_auth_resp(res, 0x81, &sess.challenge[..chal_len])?;
                return Ok(());
            }
            match algo {
                ALGO_RSA1024 | ALGO_RSA2048 => {
                    check_touch(touch_policy, presence)?;
                    let mut key = seal::load_rsa_key(dev, fs, key_fid(key_ref))?;
                    let _ = key.precompute();
                    if c.len() != key.size() {
                        return Err(Sw::INCORRECT_PARAMS);
                    }
                    let m = BigUint::from_bytes_be(c);
                    let mut ad = RngAdapter(rng);
                    let pt = rsa::hazmat::rsa_decrypt_and_check(&key, Some(&mut ad), &m)
                        .map_err(|_| Sw::EXEC_ERROR)?;
                    let mut out = [0u8; 256];
                    let bytes = pt.to_bytes_be();
                    let off = key.size() - bytes.len();
                    out[..off].fill(0);
                    out[off..key.size()].copy_from_slice(&bytes);
                    dyn_auth_resp(res, 0x82, &out[..key.size()])?;
                    out.zeroize();
                }
                ALGO_ECCP256 | ALGO_ECCP384 => {
                    check_touch(touch_policy, presence)?;
                    let key = seal::load_ec_key(dev, fs, key_fid(key_ref))?;
                    let want = if algo == ALGO_ECCP256 {
                        Curve::P256
                    } else {
                        Curve::P384
                    };
                    if key.curve() != want {
                        return Err(Sw::INCORRECT_P1P2);
                    }
                    let mut raw = [0u8; 96];
                    let rn = key.sign(c, rng, &mut raw)?;
                    let mut der = [0u8; 112];
                    let dn = x509::ecdsa_sig_der(&raw[..rn], &mut der)?;
                    dyn_auth_resp(res, 0x82, &der[..dn])?;
                }
                ALGO_3DES | ALGO_AES128 | ALGO_AES192 | ALGO_AES256 => {
                    if key_ref != SLOT_CARDMGM {
                        return Err(Sw::INCORRECT_P1P2);
                    }
                    check_touch(touch_policy, presence)?;
                    if c.len() != chal_len {
                        return Err(Sw::DATA_INVALID);
                    }
                    let mut enc = [0u8; 16];
                    enc[..chal_len].copy_from_slice(c);
                    mgm_crypt(
                        algo,
                        &mgm_key[..mgm_len],
                        &mut enc[..chal_len],
                        Dir::Encrypt,
                    )?;
                    dyn_auth_resp(res, 0x82, &enc[..chal_len])?;
                }
                _ => return Err(WRONG_DATA),
            }
            return Ok(());
        }

        if let Some(r) = t82
            && !r.is_empty()
        {
            // Single auth step 2: verify the host-encrypted challenge.
            if key_ref != SLOT_CARDMGM {
                return Err(Sw::INCORRECT_P1P2);
            }
            if !sess.has_challenge {
                return Err(Sw::INCORRECT_PARAMS);
            }
            check_touch(touch_policy, presence)?;
            sess.has_challenge = false;
            if r.len() != chal_len {
                return Err(Sw::DATA_INVALID);
            }
            let mut dec = [0u8; 16];
            dec[..chal_len].copy_from_slice(r);
            mgm_crypt(
                algo,
                &mgm_key[..mgm_len],
                &mut dec[..chal_len],
                Dir::Decrypt,
            )?;
            if !ct_eq(&dec[..chal_len], &sess.challenge[..chal_len]) {
                return Err(Sw::DATA_INVALID);
            }
            sess.has_mgm = true;
            return Ok(());
        }

        if let Some(pp) = t85.filter(|p| !p.is_empty()) {
            // ECDH (tag 0x85, "exponentiation") for the key-management slots.
            if !is_key(key_ref) {
                return Err(Sw::INCORRECT_P1P2);
            }
            if !matches!(algo, ALGO_ECCP256 | ALGO_ECCP384) {
                return Err(Sw::INCORRECT_P1P2);
            }
            check_touch(touch_policy, presence)?;
            let key = seal::load_ec_key(dev, fs, key_fid(key_ref))?;
            let want = if algo == ALGO_ECCP256 {
                Curve::P256
            } else {
                Curve::P384
            };
            if key.curve() != want {
                return Err(Sw::INCORRECT_P1P2);
            }
            let mut shared = [0u8; 48];
            let n = key.ecdh(pp, &mut shared)?;
            dyn_auth_resp(res, 0x82, &shared[..n])?;
            shared.zeroize();
            return Ok(());
        }

        Ok(())
    })();
    mgm_key.zeroize();

    match sw {
        Ok(()) => {
            if pinpol == PINPOLICY_ALWAYS {
                sess.has_pin = false;
            }
            Sw::OK
        }
        Err(e) => e,
    }
}
