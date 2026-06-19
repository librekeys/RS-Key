// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIV file ids, the wire-object map and first-boot defaults. One `Fs` is
//! shared across all applets, so PIV owns its own disjoint fid ranges:
//! keys/PINs at `0xD1xx` (low byte = wire slot), data objects at `0xD2xx` (low
//! byte of the `5FC1xx` object id) — the wire slot is the fid low byte everywhere.

use rsk_crypto::Device;
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{Curve, PrivKey};
use rsk_sdk::Sw;
use zeroize::Zeroize;

use crate::seal;
use crate::x509;

// PIV algorithm identifiers (SP 800-78 / Yubico).
pub const ALGO_3DES: u8 = 0x03;
pub const ALGO_RSA3072: u8 = 0x05;
pub const ALGO_RSA1024: u8 = 0x06;
pub const ALGO_RSA2048: u8 = 0x07;
pub const ALGO_AES128: u8 = 0x08;
pub const ALGO_AES192: u8 = 0x0A;
pub const ALGO_AES256: u8 = 0x0C;
pub const ALGO_ECCP256: u8 = 0x11;
pub const ALGO_ECCP384: u8 = 0x14;
pub const ALGO_RSA4096: u8 = 0x16;
pub const ALGO_X25519: u8 = 0xE1;

// PIN / touch policies (Yubico metadata values).
pub const PINPOLICY_DEFAULT: u8 = 0;
pub const PINPOLICY_NEVER: u8 = 1;
pub const PINPOLICY_ONCE: u8 = 2;
pub const PINPOLICY_ALWAYS: u8 = 3;
pub const TOUCHPOLICY_NEVER: u8 = 1;
pub const TOUCHPOLICY_ALWAYS: u8 = 2;
pub const TOUCHPOLICY_CACHED: u8 = 3;

pub const ORIGIN_GENERATED: u8 = 0x01;
pub const ORIGIN_IMPORTED: u8 = 0x02;

// Wire key references.
pub const SLOT_AUTHENTICATION: u8 = 0x9A;
pub const SLOT_CARDMGM: u8 = 0x9B;
pub const SLOT_SIGNATURE: u8 = 0x9C;
pub const SLOT_KEYMGM: u8 = 0x9D;
pub const SLOT_CARDAUTH: u8 = 0x9E;
pub const SLOT_ATTESTATION: u8 = 0xF9;

/// The twenty retired key-management slots.
pub fn is_retired(slot: u8) -> bool {
    (0x82..=0x95).contains(&slot)
}

/// The four primary asymmetric slots.
pub fn is_active(slot: u8) -> bool {
    matches!(
        slot,
        SLOT_AUTHENTICATION | SLOT_SIGNATURE | SLOT_KEYMGM | SLOT_CARDAUTH
    )
}

/// Any movable/attestable asymmetric slot (excludes 9B and F9).
pub fn is_key(slot: u8) -> bool {
    is_active(slot) || is_retired(slot)
}

/// Private-key file for a wire slot (also 9B and F9). A [`KeyFid`]: its contents
/// are AES-256-GCM-sealed ([`seal`]), so the slot can only be reached through the
/// typed key API, never the plaintext `Fs::put`/`read`.
pub fn key_fid(slot: u8) -> KeyFid {
    KeyFid::new(0xD100 | slot as u16)
}

/// PIN / PUK verifier files: `[len, format=0x01, verifier(32)]`.
pub const EF_PIN: u16 = 0xD180;
pub const EF_PUK: u16 = 0xD181;
/// Retry state: `[pin_total, pin_left, puk_total, puk_left]`.
pub const EF_RETRIES: u16 = 0xD1FE;

/// The X.509 certificate object that pairs with a key slot:
/// `5FC105/0A/0B/01` for the active four, `5FC10D…5FC120` for retired 1–20
/// (= slot + 0x8B), `5FFF01` for F9.
pub fn cert_fid_for_slot(slot: u8) -> Option<u16> {
    Some(match slot {
        SLOT_AUTHENTICATION => 0xD205,
        SLOT_SIGNATURE => 0xD20A,
        SLOT_KEYMGM => 0xD20B,
        SLOT_CARDAUTH => 0xD201,
        SLOT_ATTESTATION => EF_ATTESTATION_CERT,
        s if is_retired(s) => 0xD200 | ((s as u16 + 0x8B) & 0xFF),
        _ => return None,
    })
}

/// The F9 attestation certificate object (`5FFF01`).
pub const EF_ATTESTATION_CERT: u16 = 0xD2F1;

/// Map a GET/PUT DATA object id (the `5C` tag value, 1–3 bytes big-endian) to
/// its file — the GET DATA allow-list: the `5FC1xx` objects, the discovery
/// object (`0x7E`, dynamic — `None` here), the BIT group template (`0x7F61`,
/// never populated) and the Yubico attestation cert (low 16 bits `0xFF01`).
pub fn object_fid(id: u32) -> Option<u16> {
    if id & 0xFFFF00 == 0x5FC100 {
        return Some(0xD200 | (id & 0xFF) as u16);
    }
    match id & 0xFFFF {
        0xFF01 => Some(EF_ATTESTATION_CERT),
        0x7F61 => Some(0xD2B6), // BITGT: a valid id with no data → 6A82
        _ => None,
    }
}

pub const DISCOVERY_ID: u32 = 0x7E;

/// The discovery object (returned raw, not wrapped in `53`): the full PIV AID
/// + PIN-usage policy `40 10`.
pub const DISCOVERY: &[u8] = &[
    0x7E, 0x12, 0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x5F,
    0x2F, 0x02, 0x40, 0x10,
];

/// Default credentials: PIN `123456` padded to 8 with `0xFF`, PUK `12345678`,
/// management key `0102…08` ×3 typed as AES-192 (the YubiKey 5.7-era default
/// key type).
pub const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
pub const DEFAULT_PUK: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
pub const DEFAULT_MGM: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
pub const DEFAULT_RETRIES: u8 = 3;

/// Write a PIN/PUK verifier file: `[len, 0x01, pin_derive_verifier(pin)]`.
pub fn put_pin_verifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    pin: &[u8],
) -> Result<(), Sw> {
    let mut rec = [0u8; 34];
    rec[0] = pin.len() as u8;
    rec[1] = 0x01;
    rec[2..].copy_from_slice(&dev.pin_derive_verifier(pin));
    let r = fs.put(fid, &rec).map_err(|_| Sw::MEMORY_FAILURE);
    rec.zeroize();
    r
}

/// Create the PIN/PUK/retry files, the default management key and the F9
/// attestation key + its self-signed P-384 certificate on first use.
/// Idempotent — every step is guarded by a has-data check.
pub fn scan_files<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Result<(), Sw> {
    if !fs.has_data(EF_PIN) {
        put_pin_verifier(dev, fs, EF_PIN, &DEFAULT_PIN)?;
    }
    if !fs.has_data(EF_PUK) {
        put_pin_verifier(dev, fs, EF_PUK, &DEFAULT_PUK)?;
    }
    if !fs.has_data(EF_RETRIES) {
        let d = DEFAULT_RETRIES;
        fs.put(EF_RETRIES, &[d, d, d, d])
            .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    if !fs.has_key(key_fid(SLOT_CARDMGM)) {
        let mut key = DEFAULT_MGM;
        let r = seal::seal_put(dev, fs, rng, key_fid(SLOT_CARDMGM), &key);
        key.zeroize();
        r?;
        // Real YubiKey 5 ships the management key touch-OFF; we follow that
        // (admin provisioning isn't touch-gated) while still enforcing it if a
        // host raises it via SET MGM KEY. Slot keys keep their ALWAYS default.
        fs.meta_add(
            key_fid(SLOT_CARDMGM).get(),
            &[ALGO_AES192, PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER],
        )
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    if !fs.has_key(key_fid(SLOT_ATTESTATION)) {
        let key = PrivKey::generate(Curve::P384, rng).ok_or(Sw::EXEC_ERROR)?;
        seal::store_ec_key(dev, fs, rng, key_fid(SLOT_ATTESTATION), &key)?;
        let mut point = [0u8; 97];
        let plen = key.public_point(&mut point)?;
        let mut cert = [0u8; x509::MAX_CERT];
        let n = x509::build_cert(
            &x509::CertParams {
                subject_slot: SLOT_ATTESTATION,
                algo: ALGO_ECCP384,
                spki: x509::Spki::Ec {
                    curve: Curve::P384,
                    point: &point[..plen],
                },
                attestation: None,
                ca_pathlen: Some(1),
            },
            &x509::Signer::Ec(&key),
            rng,
            &mut cert,
        )?;
        let mut obj = [0u8; x509::MAX_CERT + 16];
        let on = crate::wrap_cert_object(&cert[..n], &mut obj);
        fs.put(EF_ATTESTATION_CERT, &obj[..on])
            .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    Ok(())
}

/// Factory-reset the applet: delete every PIV file and meta record
/// (`0xD100..=0xD2FF`), then re-create the defaults. Scoped to the PIV fid
/// range — the other applets' data must survive a PIV reset.
pub fn reset_files<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Result<(), Sw> {
    // Sweep in bounded batches until no PIV fid remains (a single pass could
    // overflow the scratch list — up to ~60 files exist after heavy use). The
    // sweep count is capped so a persistently failing delete cannot spin.
    for _ in 0..8 {
        let mut fids = [0u16; 32];
        let mut n = 0;
        fs.for_each_key(&mut |fid| {
            if (0xD100..=0xD2FF).contains(&fid) && n < fids.len() {
                fids[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            break;
        }
        for &fid in &fids[..n] {
            let _ = fs.delete(fid);
            let _ = fs.meta_delete(fid);
        }
    }
    scan_files(dev, fs, rng)
}
