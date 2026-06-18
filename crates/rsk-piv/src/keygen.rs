// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERATE ASYMMETRIC KEY PAIR (0x47), IMPORT ASYMMETRIC KEY (0xFE) and
//! ATTESTATION (0xF9). Generation writes a self-signed certificate into the
//! slot's certificate object (`70/71/FE`-wrapped, as `ykman` expects) so GET
//! DATA serves one immediately; IMPORT requires management-key auth.

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{
    Curve, PrivKey, generate_rsa, make_ec_pubkey_do, make_rsa_response, rsa_from_pqe,
};
use rsk_sdk::tlv::find_tag;
use rsk_sdk::{ResBuf, Sw};
use zeroize::Zeroize;

use crate::files::*;
use crate::seal;
use crate::x509;
use crate::{Session, WRONG_DATA, wrap_cert_object};

/// Parsed `AC` generation template: algorithm + optional policy tags.
pub(crate) struct GenReq {
    pub algo: u8,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
}

pub(crate) fn parse_gen_template(data: &[u8]) -> Result<GenReq, Sw> {
    if data.is_empty() {
        return Err(Sw::WRONG_LENGTH);
    }
    if data[0] != 0xAC {
        return Err(WRONG_DATA);
    }
    let ac = find_tag(data, 0xAC)
        .filter(|v| !v.is_empty())
        .ok_or(WRONG_DATA)?;
    let algo = find_tag(ac, 0x80)
        .filter(|v| !v.is_empty())
        .ok_or(WRONG_DATA)?[0];
    // SP 800-131A: no RSA-1024 generation under the FIPS-style profile. This is
    // the one template parser, so it also covers the firmware prime-search path.
    if cfg!(feature = "fips-profile") && algo == ALGO_RSA1024 {
        return Err(WRONG_DATA);
    }
    let pin_policy = find_tag(ac, 0xAA).and_then(|v| v.first().copied());
    let touch_policy = find_tag(ac, 0xAB).and_then(|v| v.first().copied());
    Ok(GenReq {
        algo,
        pin_policy,
        touch_policy,
    })
}

/// Resolve the metadata policy bytes at store time (the stored value is never
/// `DEFAULT`): signature slot defaults to PIN-always.
pub(crate) fn resolved_policies(slot: u8, req_pin: Option<u8>, req_touch: Option<u8>) -> [u8; 2] {
    let def_pin = if slot == SLOT_SIGNATURE {
        PINPOLICY_ALWAYS
    } else {
        PINPOLICY_ONCE
    };
    [
        req_pin.unwrap_or(def_pin),
        req_touch.unwrap_or(TOUCHPOLICY_ALWAYS),
    ]
}

/// Build the slot's self-signed certificate and store it (70/71/FE-wrapped)
/// in the paired certificate object.
fn store_slot_cert<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
    spki: x509::Spki,
    signer: x509::Signer,
) -> Result<(), Sw> {
    let mut cert = [0u8; x509::MAX_CERT];
    let n = x509::build_cert(
        &x509::CertParams {
            subject_slot: slot,
            algo,
            spki,
            attestation: None,
            ca_pathlen: None,
        },
        &signer,
        rng,
        &mut cert,
    )?;
    let mut obj = [0u8; x509::MAX_CERT + 16];
    let on = wrap_cert_object(&cert[..n], &mut obj);
    let fid = cert_fid_for_slot(slot).ok_or(WRONG_DATA)?;
    fs.put(fid, &obj[..on]).map_err(|_| Sw::MEMORY_FAILURE)
}

/// The EC arm of GENERATE; RSA goes through
/// [`crate::PivApplet::rsa_generate_finish`] (the firmware runs the dual-core
/// prime search, CCID keepalives flowing meanwhile) or the blocking fallback
/// below.
pub(crate) fn generate_ec<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    req: &GenReq,
    res: &mut ResBuf,
) -> Sw {
    let curve = match req.algo {
        ALGO_ECCP256 => Curve::P256,
        ALGO_ECCP384 => Curve::P384,
        _ => return WRONG_DATA,
    };
    let Some(key) = PrivKey::generate(curve, rng) else {
        return Sw::EXEC_ERROR;
    };
    let mut point = [0u8; 97];
    let plen = match key.public_point(&mut point) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = store_slot_cert(
        fs,
        rng,
        slot,
        req.algo,
        x509::Spki::Ec {
            curve,
            point: &point[..plen],
        },
        x509::Signer::Ec(&key),
    ) {
        return e;
    }
    if let Err(e) = seal::store_ec_key(dev, fs, rng, key_fid(slot), &key) {
        return e;
    }
    let pol = resolved_policies(slot, req.pin_policy, req.touch_policy);
    if fs
        .meta_add(
            key_fid(slot).get(),
            &[req.algo, pol[0], pol[1], ORIGIN_GENERATED],
        )
        .is_err()
    {
        return Sw::MEMORY_FAILURE;
    }
    let mut out = [0u8; 110];
    let n = make_ec_pubkey_do(&point[..plen], &mut out);
    if !res.extend(&out[..n]) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

/// Store a freshly generated RSA key + certificate and emit the
/// `7F49 { 81 N, 82 E }` response. Shared by the firmware keygen fast-path and
/// the blocking in-process fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_rsa<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
    pol: [u8; 2],
    key: &RsaPrivateKey,
    res: &mut ResBuf,
) -> Sw {
    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();
    if let Err(sw) = store_slot_cert(
        fs,
        rng,
        slot,
        algo,
        x509::Spki::Rsa { n: &n, e: &e },
        x509::Signer::Rsa(key),
    ) {
        return sw;
    }
    if let Err(sw) = seal::store_rsa_key(dev, fs, rng, key_fid(slot), key) {
        return sw;
    }
    if fs
        .meta_add(
            key_fid(slot).get(),
            &[algo, pol[0], pol[1], ORIGIN_GENERATED],
        )
        .is_err()
    {
        return Sw::MEMORY_FAILURE;
    }
    let mut out = [0u8; 5 + 4 + 256 + 2 + 8];
    let dn = make_rsa_response(key, &mut out);
    if !res.extend(&out[..dn]) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

/// Blocking RSA generation — the in-process fallback (host tests; on-device the
/// firmware fast-path steps the prime search itself).
pub(crate) fn generate_rsa_blocking<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    req: &GenReq,
    res: &mut ResBuf,
) -> Sw {
    let nbits = match req.algo {
        ALGO_RSA1024 => 1024,
        ALGO_RSA2048 => 2048,
        _ => return WRONG_DATA,
    };
    let key = match generate_rsa(rng, nbits) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let pol = resolved_policies(slot, req.pin_policy, req.touch_policy);
    finish_rsa(dev, fs, rng, slot, req.algo, pol, &key, res)
}

/// IMPORT ASYMMETRIC KEY; gated on management-key auth.
pub(crate) fn import<S: Storage>(
    sess: &Session,
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    algo: u8,
    slot: u8,
    data: &[u8],
) -> Sw {
    if !is_key(slot) {
        return Sw::INCORRECT_P1P2;
    }
    if !sess.has_mgm {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // SP 800-131A: no RSA-1024 import under the FIPS-style profile either.
    if cfg!(feature = "fips-profile") && algo == ALGO_RSA1024 {
        return WRONG_DATA;
    }
    let pin_policy = find_tag(data, 0xAA).and_then(|v| v.first().copied());
    let touch_policy = find_tag(data, 0xAB).and_then(|v| v.first().copied());
    match algo {
        ALGO_RSA1024 | ALGO_RSA2048 => {
            let p = find_tag(data, 0x01).filter(|v| !v.is_empty());
            let q = find_tag(data, 0x02).filter(|v| !v.is_empty());
            let (Some(p), Some(q)) = (p, q) else {
                return WRONG_DATA;
            };
            let Some(key) = rsa_from_pqe(&[0x01, 0x00, 0x01], p, q) else {
                return Sw::EXEC_ERROR;
            };
            let want = if algo == ALGO_RSA1024 { 128 } else { 256 };
            if key.size() != want {
                return WRONG_DATA;
            }
            if let Err(sw) = seal::store_rsa_key(dev, fs, rng, key_fid(slot), &key) {
                return sw;
            }
        }
        ALGO_ECCP256 | ALGO_ECCP384 => {
            let Some(scalar) = find_tag(data, 0x06).filter(|v| !v.is_empty()) else {
                return WRONG_DATA;
            };
            let curve = if algo == ALGO_ECCP256 {
                Curve::P256
            } else {
                Curve::P384
            };
            let field = if algo == ALGO_ECCP256 { 32 } else { 48 };
            if scalar.len() > field {
                return WRONG_DATA;
            }
            let Some(key) = PrivKey::from_scalar(curve, scalar) else {
                return WRONG_DATA;
            };
            // Reject the zero/invalid scalar early: deriving the public point
            // fails for out-of-range keys.
            let mut pt = [0u8; 97];
            if key.public_point(&mut pt).is_err() {
                return WRONG_DATA;
            }
            if let Err(sw) = seal::store_ec_key(dev, fs, rng, key_fid(slot), &key) {
                return sw;
            }
        }
        _ => return WRONG_DATA,
    }
    let pol = resolved_policies(slot, pin_policy, touch_policy);
    if fs
        .meta_add(
            key_fid(slot).get(),
            &[algo, pol[0], pol[1], ORIGIN_IMPORTED],
        )
        .is_err()
    {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// Build an attestation certificate for a *generated* slot key, signed by the
/// F9 key, returned as bare DER (as real YubiKeys do).
pub(crate) fn attest<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    serial4: [u8; 4],
    res: &mut ResBuf,
) -> Sw {
    if !is_key(slot) {
        return Sw::REFERENCE_NOT_FOUND;
    }
    if !fs.has_key(key_fid(slot)) {
        return Sw::REFERENCE_NOT_FOUND;
    }
    let mut meta = [0u8; 8];
    let Some(meta_len) = fs.meta_find(key_fid(slot).get(), &mut meta) else {
        return Sw::REFERENCE_NOT_FOUND;
    };
    if meta_len < 4 || meta[3] != ORIGIN_GENERATED {
        return Sw::INCORRECT_PARAMS;
    }
    let f9 = match seal::load_ec_key(dev, fs, key_fid(SLOT_ATTESTATION)) {
        Ok(k) => k,
        Err(e) => return e,
    };
    // The attestation serial is the device serial as a raw little-endian u32.
    let serial_le = [serial4[3], serial4[2], serial4[1], serial4[0]];
    let att = x509::AttestExt {
        firmware: [crate::VERSION.0, crate::VERSION.1, crate::VERSION.2],
        serial_le,
        policy: [meta[1], meta[2]],
    };
    let mut cert = [0u8; x509::MAX_CERT];
    let built = match meta[0] {
        ALGO_RSA1024 | ALGO_RSA2048 => {
            let key = match seal::load_rsa_key(dev, fs, key_fid(slot)) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let n = key.n().to_bytes_be();
            let e = key.e().to_bytes_be();
            x509::build_cert(
                &x509::CertParams {
                    subject_slot: slot,
                    algo: meta[0],
                    spki: x509::Spki::Rsa { n: &n, e: &e },
                    attestation: Some(att),
                    ca_pathlen: None,
                },
                &x509::Signer::Ec(&f9),
                rng,
                &mut cert,
            )
        }
        ALGO_ECCP256 | ALGO_ECCP384 => {
            let key = match seal::load_ec_key(dev, fs, key_fid(slot)) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let mut point = [0u8; 97];
            let plen = match key.public_point(&mut point) {
                Ok(n) => n,
                Err(e) => return e,
            };
            x509::build_cert(
                &x509::CertParams {
                    subject_slot: slot,
                    algo: meta[0],
                    spki: x509::Spki::Ec {
                        curve: key.curve(),
                        point: &point[..plen],
                    },
                    attestation: Some(att),
                    ca_pathlen: None,
                },
                &x509::Signer::Ec(&f9),
                rng,
                &mut cert,
            )
        }
        _ => return WRONG_DATA,
    };
    let n = match built {
        Ok(n) => n,
        Err(e) => return e,
    };
    let ok = res.extend(&cert[..n]);
    cert.zeroize();
    if !ok {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}
