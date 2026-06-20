// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! authenticatorVendor (0x41) — wallet-style seed backup over an MSE channel.
//!
//! Lets the host read the device's 32-byte master seed once, at setup, to render
//! it as a BIP-39 / SLIP-39 mnemonic, and write a seed back when restoring onto a
//! fresh device. Six subcommands under CTAP command `0x41`:
//!
//! - `MSE` (0x01) — P-256 ECDH key agreement → a ChaCha20-Poly1305 channel.
//! - `BACKUP_EXPORT` (0x02) — hand the seed to the host over that channel (gated).
//! - `BACKUP_LOAD` (0x03) — install a seed from the host, re-sealed to this chip.
//! - `BACKUP_FINALIZE` (0x04) — seal the one-time export window.
//! - `BACKUP_STATE` (0x05) — read `{sealed, has_seed, locked, unlocked}`.
//! - `UNLOCK` (0x06) — soft-lock: decrypt `EF_KEY_DEV_ENC` into RAM for this
//!   power cycle. The lock is engaged and released by `authenticatorConfig`
//!   vendor ids AUT_ENABLE / AUT_DISABLE ([`crate::config`]).
//!
//! Exporting the seed is the one place a FIDO authenticator hands out a
//! normally non-exportable key, so it is the most-gated command here: a
//! one-time setup window (reopened only by an authenticatorReset) AND physical
//! touch AND, when a PIN is set, a pinUvAuthToken. Every message uses a fresh
//! random nonce, so an export and a load sharing one channel cannot reuse one.
//! The soft lock also wraps the seed *value*, so backup and lock stay orthogonal.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::mac::hkdf_sha256;
use rsk_crypto::mlkem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, mlkem768_encapsulate};
use rsk_crypto::pinproto::{PinProto, ecdh_raw};
use rsk_crypto::sha256;
use rsk_fs::Storage;

use crate::cbordec::{cbor, def_map};
use crate::cert;
use crate::consts::{
    CTAP_VENDOR, EF_ATT_CHAIN, EF_ATT_KEY, EF_BACKUP_SEALED, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC,
    EF_PIN, VENDOR_ATT_CLEAR, VENDOR_ATT_IMPORT, VENDOR_ATT_STATE, VENDOR_AUDIT_CHECKPOINT,
    VENDOR_AUDIT_READ, VENDOR_BACKUP_EXPORT, VENDOR_BACKUP_FINALIZE, VENDOR_BACKUP_LOAD,
    VENDOR_BACKUP_STATE, VENDOR_MSE, VENDOR_UNLOCK,
};
use crate::cose::cose_key_ecdh;
use crate::ec::P256Key;
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::{
    LOCK_BLOB_LEN, encrypt_keydev_f1, ensure_seed, lock_engaged, open_seed_locked, store_att_key,
};
use crate::state::PERM_ACFG;
use crate::{Ctx, Rng};

const BLOB_LEN: usize = 12 + 32 + 16; // nonce ‖ ciphertext(seed) ‖ tag
// Sized for ATT_IMPORT's wrapped key + a full cert chain (≤ 2048 B); every
// other subcommand stays tiny. The pinUvAuth MAC covers these bytes verbatim.
const MAX_RAW_SUBPARA: usize = 2200;

#[derive(Default)]
struct Req<'a> {
    subcommand: u64,
    kax: &'a [u8],
    kay: &'a [u8],
    /// MSE subCommandParams key 2 (optional): the host's ML-KEM-768 encapsulation
    /// key (1184 B). When present, the MSE channel is hybrid P-256 + ML-KEM-768.
    mlkem_ek: &'a [u8],
    blob: &'a [u8],
    /// ATT_IMPORT subCommandParams key 2: the DER cert chain, leaf first.
    chain: &'a [u8],
    raw_subpara: &'a [u8],
    proto: u64,
    pin_uv_auth_param: Option<&'a [u8]>,
}

/// `{1: subcommand, 2: subCommandParams, 3: pinUvAuthProtocol, 4: pinUvAuthParam}`.
/// `subCommandParams` carries either the host COSE key (MSE) or the 60-byte blob
/// (LOAD); its raw bytes are captured for the pinUvAuth MAC.
fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req::default();
    let n = def_map(&mut d)?;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => {
                let start = d.position();
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    let sk = cbor(d.i32())?;
                    if sk == 1 && req.subcommand == VENDOR_MSE {
                        // COSE_Key{1:2, 3:-25, -1:1, -2:x, -3:y}
                        let c = def_map(&mut d)?;
                        for _ in 0..c {
                            match cbor(d.i32())? {
                                -2 => req.kax = cbor(d.bytes())?,
                                -3 => req.kay = cbor(d.bytes())?,
                                _ => cbor(d.skip())?,
                            }
                        }
                    } else if sk == 1
                        && matches!(
                            req.subcommand,
                            VENDOR_BACKUP_LOAD
                                | VENDOR_UNLOCK
                                | VENDOR_AUDIT_CHECKPOINT
                                | VENDOR_ATT_IMPORT
                        )
                    {
                        req.blob = cbor(d.bytes())?;
                    } else if sk == 2 && req.subcommand == VENDOR_ATT_IMPORT {
                        req.chain = cbor(d.bytes())?;
                    } else if sk == 2 && req.subcommand == VENDOR_MSE {
                        req.mlkem_ek = cbor(d.bytes())?;
                    } else {
                        cbor(d.skip())?;
                    }
                }
                req.raw_subpara = &data[start..d.position()];
            }
            3 => req.proto = cbor(d.u32())? as u64,
            4 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Right-align a COSE coordinate into 32 bytes.
fn coord(src: &[u8]) -> Result<[u8; 32], CtapError> {
    if src.len() > 32 {
        return Err(CtapError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    out[32 - src.len()..].copy_from_slice(src);
    Ok(out)
}

fn encode<F>(out: &mut [u8], f: F) -> Result<usize, CtapError>
where
    F: FnOnce(
        &mut Encoder<Cursor<&mut [u8]>>,
    ) -> Result<(), minicbor::encode::Error<minicbor::encode::write::EndOfSlice>>,
{
    let mut enc = Encoder::new(Cursor::new(out));
    f(&mut enc).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

pub fn vendor<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, data: &[u8], out: &mut [u8]) -> CtapResult {
    let req = parse(data)?;
    match req.subcommand {
        VENDOR_MSE => mse(ctx, &req, out),
        VENDOR_BACKUP_EXPORT => backup_export(ctx, &req, out),
        VENDOR_BACKUP_LOAD => backup_load(ctx, &req),
        VENDOR_BACKUP_FINALIZE => backup_finalize(ctx),
        VENDOR_BACKUP_STATE => backup_state(ctx, out),
        VENDOR_UNLOCK => unlock(ctx, &req),
        VENDOR_AUDIT_READ => audit_read(ctx, &req, out),
        VENDOR_AUDIT_CHECKPOINT => audit_checkpoint(ctx, &req, out),
        VENDOR_ATT_IMPORT => att_import(ctx, &req),
        VENDOR_ATT_CLEAR => att_clear(ctx, &req),
        VENDOR_ATT_STATE => att_state(ctx, out),
        _ => Err(CtapError::InvalidParameter),
    }
}

/// `ATT_IMPORT`: install an org attestation key + DER chain (leaf first). The
/// P-256 scalar arrives ChaCha-wrapped on the MSE channel (the same 60-byte
/// blob as the lock key); the chain is public certificate material and travels
/// in the clear, MAC-covered like every subCommandParams. Gated like a seed
/// move (MSE + PIN + touch). Survives authenticatorReset — it is
/// org-provisioned *device* identity; ATT_CLEAR removes it.
fn att_import<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    let mut packed = [0u8; cert::ATT_CHAIN_MAX + 1 + 2 * cert::ATT_CHAIN_MAX_CERTS];
    let plen = cert::att_chain_pack(req.chain, &mut packed).ok_or(CtapError::InvalidParameter)?;
    gate(ctx, req)?;
    let mut scalar = open_channel_key(ctx, req.blob)?;
    if P256Key::from_scalar(&scalar).is_none() {
        scalar.zeroize();
        return Err(CtapError::InvalidParameter);
    }
    let r = store_att_key(&ctx.dev, ctx.fs, &scalar);
    scalar.zeroize();
    r.map_err(|_| CtapError::Other)?;
    ctx.fs
        .put(EF_ATT_CHAIN, &packed[..plen])
        .map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_ATT_IMPORT, 0, &[]);
    Ok(0)
}

/// `ATT_CLEAR`: drop the org attestation (same gate as the import).
fn att_clear<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    gate(ctx, req)?;
    let _ = ctx.fs.delete_key(EF_ATT_KEY);
    let _ = ctx.fs.delete(EF_ATT_CHAIN);
    journal::append(ctx, journal::EV_ATT_CLEAR, 0, &[]);
    Ok(0)
}

/// `ATT_STATE`: `{1: present, 2: sha256(packed chain)}` — ungated, like
/// BACKUP_STATE; the chain itself is public.
fn att_state<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let mut chain = [0u8; cert::ATT_CHAIN_MAX + 1 + 2 * cert::ATT_CHAIN_MAX_CERTS];
    let present = ctx.fs.has_key(EF_ATT_KEY);
    let n = ctx.fs.read(EF_ATT_CHAIN, &mut chain).unwrap_or(0);
    encode(out, |e| {
        e.map(if present && n > 0 { 2 } else { 1 })?
            .u8(1)?
            .bool(present)?;
        if present && n > 0 {
            e.u8(2)?.bytes(&sha256(&chain[..n]))?;
        }
        Ok(())
    })
}

/// `AUDIT_READ`: export the journal window (`journal::vendor_read`). Gated on a
/// PIN token (when a PIN is set) only — the entries are pseudonymous and no key
/// material moves, so no MSE channel and no touch.
fn audit_read<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    pin_gate(ctx, req)?;
    journal::vendor_read(ctx, out)
}

/// `AUDIT_CHECKPOINT`: sign the chain head (`journal::vendor_checkpoint`).
/// PIN token plus a physical touch; the subCommandParams blob is the host's
/// freshness challenge (≤ 32 bytes).
fn audit_checkpoint<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    out: &mut [u8],
) -> CtapResult {
    pin_gate(ctx, req)?;
    if !ctx.check_user_presence() {
        return Err(CtapError::OperationDenied);
    }
    journal::vendor_checkpoint(ctx, req.blob, out)
}

/// Decrypt the channel-wrapped 32-byte lock key carried in `blob`
/// (nonce ‖ ct ‖ tag, AAD = the device MSE public key). Shared with the
/// `authenticatorConfig` AUT_ENABLE arm.
pub(crate) fn open_channel_key<S: Storage, R: Rng>(
    ctx: &Ctx<S, R>,
    blob: &[u8],
) -> Result<[u8; 32], CtapError> {
    if blob.len() != LOCK_BLOB_LEN {
        return Err(CtapError::InvalidParameter);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(
        &ctx.state.mse_key,
        &nonce,
        &ctx.state.mse_pub,
        &mut key,
        &tag,
    ) {
        Ok(()) => Ok(key),
        Err(_) => {
            key.zeroize();
            Err(CtapError::InvalidParameter)
        }
    }
}

/// `UNLOCK`: the host sends the 32-byte lock key over the MSE channel; the
/// wrapped seed on flash decrypts into RAM ([`crate::FidoState::keydev_dec`])
/// and FIDO operations work until power-off. No PIN or touch gate — knowing
/// the 256-bit lock key *is* the authorization, and this runs on every
/// power-up of a locked device.
fn unlock<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    if !ctx.state.mse_active {
        return Err(CtapError::NotAllowed);
    }
    let mut lock_key = open_channel_key(ctx, req.blob)?;
    if !lock_engaged(ctx.fs) {
        lock_key.zeroize();
        return Err(CtapError::IntegrityFailure);
    }
    let mut blob = [0u8; LOCK_BLOB_LEN];
    let n = ctx.fs.read_key(EF_KEY_DEV_ENC, &mut blob);
    let seed = n.and_then(|n| open_seed_locked(&lock_key, &blob[..n]));
    lock_key.zeroize();
    match seed {
        Some(seed) => {
            ctx.state.clear_keydev_dec();
            ctx.state.keydev_dec = Some(seed);
            Ok(0)
        }
        None => Err(CtapError::InvalidParameter),
    }
}

/// Domain-separation salt for the hybrid channel key — keeps the post-quantum
/// derivation disjoint from the classical one (which uses an empty salt). The
/// `v1` pins the construction `HKDF-SHA256(salt, z ‖ ss_mlkem, dev_pub ‖ ct)`.
const MSE_PQ_SALT: &[u8] = b"RSK-MSE-PQ-v1";

/// `MSE` key agreement: a fresh device ephemeral keypair, ECDH with the host key,
/// then `HKDF-SHA256(ikm = shared x, info = device pubkey)` → the 32-byte channel
/// key. Returns the device public key as a COSE ECDH key.
///
/// When the host also supplies an ML-KEM-768 encapsulation key (subCommandParams
/// key 2), the channel is **hybrid**: the device encapsulates to it and folds the
/// ML-KEM shared secret into the derivation alongside the ECDH secret
/// ([`mlkem_leg`]), returning the ciphertext as response key 2. This is the
/// harvest-now-decrypt-later defense for the seed-backup channel — recording the
/// exchange today no longer hands a future quantum adversary the channel key,
/// since recovering it needs *both* P-256 and ML-KEM-768 broken. A host that
/// sends no key 2 gets the classical channel, byte-for-byte unchanged.
fn mse<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    if req.kax.is_empty() || req.kay.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    let kax = coord(req.kax)?;
    let kay = coord(req.kay)?;

    let mut scalar = [0u8; 32];
    let (dx, dy) = loop {
        ctx.rng.fill(&mut scalar);
        if let Some(k) = P256Key::from_scalar(&scalar) {
            break k.public_xy();
        }
    };
    let mut z = match ecdh_raw(&scalar, &kax, &kay) {
        Ok(z) => z,
        Err(_) => {
            scalar.zeroize();
            return Err(CtapError::InvalidParameter);
        }
    };
    scalar.zeroize();

    let mut dev_pub = [0u8; 65];
    dev_pub[0] = 0x04;
    dev_pub[1..33].copy_from_slice(&dx);
    dev_pub[33..].copy_from_slice(&dy);

    let hybrid = !req.mlkem_ek.is_empty();
    let mut ct = [0u8; MLKEM768_CT_LEN];
    let mut key = [0u8; 32];
    let derived = if hybrid {
        mlkem_leg(ctx.rng, req.mlkem_ek, &z, &dev_pub, &mut ct, &mut key)
    } else {
        hkdf_sha256(&[], &z, &dev_pub, &mut key).map_err(|_| CtapError::Other)
    };
    z.zeroize();
    if let Err(e) = derived {
        key.zeroize();
        return Err(e);
    }
    ctx.state.mse_key = key;
    ctx.state.mse_pub = dev_pub;
    ctx.state.mse_active = true;
    key.zeroize();

    encode(out, |e| {
        e.map(if hybrid { 2 } else { 1 })?.u8(1)?;
        cose_key_ecdh(e, &dx, &dy)?;
        if hybrid {
            e.u8(2)?.bytes(&ct)?;
        }
        Ok(())
    })
}

/// The ML-KEM-768 leg of the hybrid handshake: encapsulate to the host's `ek`,
/// hand back the ciphertext for the response, and derive the channel key as
/// `HKDF-SHA256(MSE_PQ_SALT, z ‖ ss_mlkem, dev_pub ‖ ct)`. Both shared secrets go
/// into the IKM (a break of either primitive leaves the key safe); the ML-KEM
/// ciphertext is bound through `info` so the key commits to the exact
/// encapsulation. A malformed `ek` — wrong length or non-reduced coefficients —
/// is rejected before any channel is established. Only `encapsulate` runs on the
/// device (the cheap ML-KEM direction); keygen and decapsulate stay on the host.
fn mlkem_leg<R: Rng>(
    rng: &mut R,
    ek: &[u8],
    z: &[u8; 32],
    dev_pub: &[u8; 65],
    ct: &mut [u8; MLKEM768_CT_LEN],
    key: &mut [u8; 32],
) -> Result<(), CtapError> {
    let ek = <&[u8; MLKEM768_EK_LEN]>::try_from(ek).map_err(|_| CtapError::InvalidParameter)?;
    let mut m = [0u8; 32];
    rng.fill(&mut m);
    let (c, mut ss) = mlkem768_encapsulate(ek, &m).map_err(|_| CtapError::InvalidParameter)?;
    m.zeroize();
    ct.copy_from_slice(&c);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(z);
    ikm[32..].copy_from_slice(&ss);
    ss.zeroize();

    let mut info = [0u8; 65 + MLKEM768_CT_LEN];
    info[..65].copy_from_slice(dev_pub);
    info[65..].copy_from_slice(ct);

    let r = hkdf_sha256(MSE_PQ_SALT, &ikm, &info, key);
    ikm.zeroize();
    r.map_err(|_| CtapError::Other)
}

/// Common gate for the seed-moving commands: an established MSE channel, physical
/// presence (touch), and — when a PIN is configured — a pinUvAuthToken with the
/// `acfg` permission over `0xff×32 ‖ 0x41 ‖ subcommand ‖ rawSubCommandParams`.
fn gate<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> Result<(), CtapError> {
    if !ctx.state.mse_active {
        return Err(CtapError::NotAllowed);
    }
    pin_gate(ctx, req)?;
    if !ctx.check_user_presence() {
        return Err(CtapError::OperationDenied);
    }
    Ok(())
}

/// The PIN half of [`gate`], shared with the audit subcommands: when a PIN is
/// configured, require a pinUvAuthToken with the `acfg` permission over
/// `0xff×32 ‖ 0x41 ‖ subcommand ‖ rawSubCommandParams`.
fn pin_gate<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> Result<(), CtapError> {
    if ctx.fs.has_data(EF_PIN) {
        let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
        let proto = PinProto::from_u64(req.proto).ok_or(CtapError::MissingParameter)?;
        if req.raw_subpara.len() > MAX_RAW_SUBPARA {
            return Err(CtapError::RequestTooLarge);
        }
        let mut vp = [0u8; 32 + 2 + MAX_RAW_SUBPARA];
        vp[..32].fill(0xff);
        vp[32] = CTAP_VENDOR;
        vp[33] = req.subcommand as u8;
        vp[34..34 + req.raw_subpara.len()].copy_from_slice(req.raw_subpara);
        let vp_len = 34 + req.raw_subpara.len();
        if !ctx.state.verify_token(proto, &vp[..vp_len], param)
            || ctx.state.paut.permissions & PERM_ACFG == 0
        {
            return Err(CtapError::PinAuthInvalid);
        }
    }
    Ok(())
}

/// `BACKUP_EXPORT`: encrypt the 32-byte seed under the MSE channel and return it.
/// Refused once the export window is sealed (finalize or a prior backup).
fn backup_export<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    // The FIPS-style profile seals the seed in entirely (non-exportable key
    // material; the MSE channel is ChaCha20-Poly1305 — not approved transport).
    // LOAD stays available: keys may migrate *into* a profile build, never out.
    if cfg!(feature = "fips-profile") {
        return Err(CtapError::NotAllowed);
    }
    if ctx.fs.has_data(EF_BACKUP_SEALED) {
        return Err(CtapError::NotAllowed);
    }
    gate(ctx, req)?;
    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let mut nonce = [0u8; 12];
    ctx.rng.fill(&mut nonce);
    let mut ct = [0u8; 32];
    ct.copy_from_slice(&seed);
    seed.zeroize();
    let tag = chacha20poly1305_encrypt(&ctx.state.mse_key, &nonce, &ctx.state.mse_pub, &mut ct);
    let mut blob = [0u8; BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(&ct);
    blob[44..].copy_from_slice(&tag);
    ct.zeroize();
    let r = encode(out, |e| {
        e.map(1)?.u8(1)?.bytes(&blob)?;
        Ok(())
    });
    blob.zeroize();
    if r.is_ok() {
        journal::append(ctx, journal::EV_BACKUP_EXPORT, 0, &[]);
    }
    r
}

/// `BACKUP_LOAD`: decrypt a seed from the host and install it, re-sealed under
/// this chip's kbase. The attestation cert (signed by the old seed scalar) is
/// rebuilt over the new seed. Refused while soft-locked — a restore next to a
/// live wrapped blob would leave two competing seeds; disable the lock (or
/// reset) first.
fn backup_load<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    if req.blob.len() != BLOB_LEN {
        return Err(CtapError::MissingParameter);
    }
    if lock_engaged(ctx.fs) {
        return Err(CtapError::NotAllowed);
    }
    gate(ctx, req)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&req.blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&req.blob[44..]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&req.blob[12..44]);
    let r = chacha20poly1305_decrypt(
        &ctx.state.mse_key,
        &nonce,
        &ctx.state.mse_pub,
        &mut seed,
        &tag,
    );
    if r.is_err() {
        seed.zeroize();
        return Err(CtapError::IntegrityFailure);
    }
    if P256Key::from_scalar(&seed).is_none() {
        seed.zeroize();
        return Err(CtapError::InvalidParameter);
    }
    let res = encrypt_keydev_f1(&ctx.dev, ctx.fs, &seed);
    seed.zeroize();
    res.map_err(|_| CtapError::Other)?;
    let _ = ctx.fs.delete(EF_EE_DEV);
    ensure_seed(&ctx.dev, ctx.fs, ctx.rng).map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_BACKUP_LOAD, 0, &[]);
    Ok(0)
}

/// `BACKUP_FINALIZE`: seal the one-time export window (a reset reopens it).
fn backup_finalize<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if !ctx.check_user_presence() {
        return Err(CtapError::OperationDenied);
    }
    ctx.fs
        .put(EF_BACKUP_SEALED, &[1])
        .map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_BACKUP_FINALIZE, 0, &[]);
    Ok(0)
}

/// `BACKUP_STATE`: `{1: sealed, 2: has_seed, 3: locked, 4: unlocked}` — ungated,
/// for host-side status. `locked` is the flash state (the wrapped blob is what's
/// stored); `unlocked` says a RAM copy from a vendor UNLOCK is live this power
/// cycle.
fn backup_state<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let sealed = ctx.fs.has_data(EF_BACKUP_SEALED);
    let has_seed = ctx.fs.has_key(EF_KEY_DEV);
    let locked = lock_engaged(ctx.fs);
    let unlocked = ctx.state.keydev_dec.is_some();
    encode(out, |e| {
        e.map(4)?
            .u8(1)?
            .bool(sealed)?
            .u8(2)?
            .bool(has_seed)?
            .u8(3)?
            .bool(locked)?
            .u8(4)?
            .bool(unlocked)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{ensure_seed, load_keydev};
    use crate::{AlwaysConfirm, FidoState, Presence, UserPresence};
    use rsk_crypto::Device;
    use rsk_crypto::MlKem768Pair;
    use rsk_crypto::mlkem::MLKEM768_SEED_LEN;
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

    struct Decline;
    impl UserPresence for Decline {
        fn request(&mut self) -> Presence {
            Presence::Timeout
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    /// The full host channel: the 32-byte key and 65-byte device pubkey (AAD), so
    /// tests can encrypt/decrypt blobs exactly as the real host tool does.
    struct Host {
        key: [u8; 32],
        aad: [u8; 65],
    }

    fn call(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        state: &mut FidoState,
        presence: &mut dyn UserPresence,
        req: &[u8],
        out: &mut [u8],
    ) -> CtapResult {
        let mut ctx = Ctx {
            dev: dev(),
            fs,
            rng,
            state,
            now_ms: 0,
            presence,
        };
        vendor(&mut ctx, req, out)
    }

    fn build_mse(buf: &mut [u8], hx: &[u8; 32], hy: &[u8; 32]) -> usize {
        let mut e = Encoder::new(Cursor::new(buf));
        e.map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(VENDOR_MSE)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(-25)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(hx)
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(hy)
            .unwrap();
        e.writer().position()
    }

    /// Run the MSE handshake host-side and return the derived channel.
    fn handshake(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, state: &mut FidoState) -> Host {
        let host_scalar = [0x42u8; 32];
        let (hx, hy) = P256Key::from_scalar(&host_scalar).unwrap().public_xy();
        let mut req = [0u8; 200];
        let n = build_mse(&mut req, &hx, &hy);
        let mut out = [0u8; 200];
        let r = call(fs, rng, state, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();

        // parse {1: COSE_Key{...,-2:dx,-3:dy}}
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.u8().unwrap(), 1);
        let c = d.map().unwrap().unwrap();
        let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
        for _ in 0..c {
            match d.i32().unwrap() {
                -2 => dx.copy_from_slice(d.bytes().unwrap()),
                -3 => dy.copy_from_slice(d.bytes().unwrap()),
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        let z = ecdh_raw(&host_scalar, &dx, &dy).unwrap();
        let mut aad = [0u8; 65];
        aad[0] = 0x04;
        aad[1..33].copy_from_slice(&dx);
        aad[33..].copy_from_slice(&dy);
        let mut key = [0u8; 32];
        hkdf_sha256(&[], &z, &aad, &mut key).unwrap();
        Host { key, aad }
    }

    /// MSE request with the optional ML-KEM-768 encapsulation key in
    /// subCommandParams key 2 — `{1: MSE, 2: {1: COSE_Key, 2: ek}}`.
    fn build_mse_hybrid(buf: &mut [u8], hx: &[u8; 32], hy: &[u8; 32], ek: &[u8]) -> usize {
        let mut e = Encoder::new(Cursor::new(buf));
        e.map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(VENDOR_MSE)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(-25)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(hx)
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(hy)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(ek)
            .unwrap();
        e.writer().position()
    }

    /// Run the hybrid MSE handshake host-side: send a P-256 pubkey plus a fresh
    /// ML-KEM-768 encapsulation key, then recompute the channel key from the ECDH
    /// secret and the decapsulated ML-KEM secret exactly as [`mlkem_leg`] does.
    fn handshake_pq(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, state: &mut FidoState) -> Host {
        let host_scalar = [0x42u8; 32];
        let (hx, hy) = P256Key::from_scalar(&host_scalar).unwrap().public_xy();

        // The host is the decapsulator: it keeps the ML-KEM keypair and ships ek.
        let pair = MlKem768Pair::from_seed(&[0x55u8; MLKEM768_SEED_LEN]);
        let ek = pair.encapsulation_key();

        let mut req = [0u8; 1400];
        let n = build_mse_hybrid(&mut req, &hx, &hy, &ek);
        let mut out = [0u8; 1400];
        let r = call(fs, rng, state, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();

        // parse {1: COSE_Key{...,-2:dx,-3:dy}, 2: ct}
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(2));
        assert_eq!(d.u8().unwrap(), 1);
        let c = d.map().unwrap().unwrap();
        let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
        for _ in 0..c {
            match d.i32().unwrap() {
                -2 => dx.copy_from_slice(d.bytes().unwrap()),
                -3 => dy.copy_from_slice(d.bytes().unwrap()),
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        assert_eq!(d.u8().unwrap(), 2);
        let mut ct = [0u8; MLKEM768_CT_LEN];
        ct.copy_from_slice(d.bytes().unwrap());

        let z = ecdh_raw(&host_scalar, &dx, &dy).unwrap();
        let ss = pair.decapsulate(&ct);
        let mut aad = [0u8; 65];
        aad[0] = 0x04;
        aad[1..33].copy_from_slice(&dx);
        aad[33..].copy_from_slice(&dy);

        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&z);
        ikm[32..].copy_from_slice(&ss);
        let mut info = [0u8; 65 + MLKEM768_CT_LEN];
        info[..65].copy_from_slice(&aad);
        info[65..].copy_from_slice(&ct);
        let mut key = [0u8; 32];
        hkdf_sha256(MSE_PQ_SALT, &ikm, &info, &mut key).unwrap();
        Host { key, aad }
    }

    fn one_byte_req(buf: &mut [u8], subcmd: u64) -> usize {
        let mut e = Encoder::new(Cursor::new(buf));
        e.map(1).unwrap().u8(1).unwrap().u64(subcmd).unwrap();
        e.writer().position()
    }

    fn load_req(buf: &mut [u8], blob: &[u8]) -> usize {
        let mut e = Encoder::new(Cursor::new(buf));
        e.map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(VENDOR_BACKUP_LOAD)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(blob)
            .unwrap();
        e.writer().position()
    }

    fn setup() -> (Fs<RamStorage>, SeqRng, FidoState) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        (fs, rng, FidoState::new())
    }

    #[cfg(feature = "fips-profile")]
    #[test]
    fn fips_backup_export_refused() {
        let (mut fs, mut rng, mut st) = setup();
        st.mse_active = true; // even over a live channel the seed is sealed in
        let mut req = [0u8; 16];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 64];
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::NotAllowed)
        );
    }

    /// ChaCha-wrap a 32-byte value for the channel (the ATT_IMPORT/LOAD shape).
    fn wrap32(host: &Host, value: &[u8; 32]) -> [u8; 60] {
        let nonce = [0x24u8; 12];
        let mut ct = *value;
        let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut ct);
        let mut blob = [0u8; 60];
        blob[..12].copy_from_slice(&nonce);
        blob[12..44].copy_from_slice(&ct);
        blob[44..].copy_from_slice(&tag);
        blob
    }

    fn att_import_req(buf: &mut [u8], blob: &[u8; 60], chain: &[u8]) -> usize {
        let mut e = Encoder::new(Cursor::new(buf));
        e.map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(VENDOR_ATT_IMPORT)
            .unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.u8(1).unwrap().bytes(blob).unwrap();
        e.u8(2).unwrap().bytes(chain).unwrap();
        e.writer().position()
    }

    #[test]
    fn att_import_state_clear_roundtrip() {
        let (mut fs, mut rng, mut st) = setup();
        let host = handshake(&mut fs, &mut rng, &mut st);

        // Import an org key + two fake-TLV certs over the channel.
        let org_scalar = [0x21u8; 32];
        let blob = wrap32(&host, &org_scalar);
        let chain: &[u8] = &[0x30, 0x03, 1, 2, 3, 0x30, 0x02, 7, 7];
        let mut req = [0u8; 256];
        let n = att_import_req(&mut req, &blob, chain);
        let mut out = [0u8; 128];
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        // The stored key decrypts back to the imported scalar; STATE says so.
        assert_eq!(
            crate::seed::load_att_key(&dev(), &mut fs).unwrap(),
            org_scalar
        );
        let n = one_byte_req(&mut req, VENDOR_ATT_STATE);
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(2));
        assert_eq!(d.u8().unwrap(), 1);
        assert!(d.bool().unwrap());

        // CLEAR drops both and STATE flips back.
        let n = one_byte_req(&mut req, VENDOR_ATT_CLEAR);
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();
        assert!(crate::seed::load_att_key(&dev(), &mut fs).is_none());
        let n = one_byte_req(&mut req, VENDOR_ATT_STATE);
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.u8().unwrap(), 1);
        assert!(!d.bool().unwrap());

        // A malformed chain is refused before any gate is consumed.
        let n = att_import_req(&mut req, &blob, &[0xFF, 0x01]);
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::InvalidParameter)
        );
    }

    #[test]
    fn mse_then_export_roundtrips_seed() {
        let (mut fs, mut rng, mut st) = setup();
        let seed = load_keydev(&dev(), &mut fs).unwrap();
        let host = handshake(&mut fs, &mut rng, &mut st);

        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        // {1: blob(60)} — decrypt it host-side.
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.u8().unwrap(), 1);
        let blob = d.bytes().unwrap();
        assert_eq!(blob.len(), BLOB_LEN);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[..12]);
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&blob[44..]);
        chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, seed);
    }

    #[test]
    fn mse_hybrid_then_export_roundtrips_seed() {
        // End-to-end proof of the hybrid channel: if the device-side ML-KEM
        // encapsulate + HKDF agrees with the host-side decapsulate + HKDF, the
        // seed exported over the channel decrypts to the real seed.
        let (mut fs, mut rng, mut st) = setup();
        let seed = load_keydev(&dev(), &mut fs).unwrap();
        let host = handshake_pq(&mut fs, &mut rng, &mut st);

        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.u8().unwrap(), 1);
        let blob = d.bytes().unwrap();
        assert_eq!(blob.len(), BLOB_LEN);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[..12]);
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&blob[44..]);
        chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, seed);
    }

    #[test]
    fn hybrid_channel_key_differs_from_classical() {
        // Same fresh device (same RNG seed → same P-256 ephemeral and ECDH
        // secret): the PQ leg must still derive a different channel key, proving
        // the ML-KEM secret and the domain salt actually participate.
        let (mut fs1, mut rng1, mut st1) = setup();
        let classical = handshake(&mut fs1, &mut rng1, &mut st1);
        let (mut fs2, mut rng2, mut st2) = setup();
        let hybrid = handshake_pq(&mut fs2, &mut rng2, &mut st2);
        assert_ne!(classical.key, hybrid.key);
    }

    #[test]
    fn mse_rejects_short_mlkem_ek() {
        // An encapsulation key one byte short is rejected before any channel
        // forms — no half-open hybrid state.
        let (mut fs, mut rng, mut st) = setup();
        let (hx, hy) = P256Key::from_scalar(&[0x42u8; 32]).unwrap().public_xy();
        let short_ek = [0u8; MLKEM768_EK_LEN - 1];
        let mut req = [0u8; 1400];
        let n = build_mse_hybrid(&mut req, &hx, &hy, &short_ek);
        let mut out = [0u8; 1400];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::InvalidParameter));
        assert!(!st.mse_active);
    }

    #[test]
    fn mse_rejects_unreduced_mlkem_ek() {
        // Right length, non-reduced coefficients → ML-KEM encapsulate fails; the
        // vendor layer maps that to InvalidParameter, no channel established.
        let (mut fs, mut rng, mut st) = setup();
        let (hx, hy) = P256Key::from_scalar(&[0x42u8; 32]).unwrap().public_xy();
        let bad_ek = [0xFFu8; MLKEM768_EK_LEN];
        let mut req = [0u8; 1400];
        let n = build_mse_hybrid(&mut req, &hx, &hy, &bad_ek);
        let mut out = [0u8; 1400];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::InvalidParameter));
        assert!(!st.mse_active);
    }

    #[test]
    fn load_installs_seed_and_rebuilds_attestation() {
        let (mut fs, mut rng, mut st) = setup();
        let old = load_keydev(&dev(), &mut fs).unwrap();
        let host = handshake(&mut fs, &mut rng, &mut st);

        // Encrypt a fresh seed host-side into a blob.
        let new_seed = [0x33u8; 32];
        let nonce = [0x07u8; 12];
        let mut buf = new_seed;
        let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut buf);
        let mut blob = [0u8; BLOB_LEN];
        blob[..12].copy_from_slice(&nonce);
        blob[12..44].copy_from_slice(&buf);
        blob[44..].copy_from_slice(&tag);

        let mut req = [0u8; 128];
        let n = load_req(&mut req, &blob);
        let mut out = [0u8; 16];
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        assert_ne!(new_seed, old);
        assert_eq!(load_keydev(&dev(), &mut fs), Some(new_seed));
        assert!(fs.has_data(EF_EE_DEV)); // attestation rebuilt over the new seed
    }

    #[test]
    fn export_refused_after_finalize() {
        let (mut fs, mut rng, mut st) = setup();
        let _ = handshake(&mut fs, &mut rng, &mut st);
        let mut req = [0u8; 32];
        let mut out = [0u8; 128];

        let n = one_byte_req(&mut req, VENDOR_BACKUP_FINALIZE);
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::NotAllowed));
    }

    #[test]
    fn export_refused_without_touch() {
        let (mut fs, mut rng, mut st) = setup();
        let _ = handshake(&mut fs, &mut rng, &mut st);
        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::OperationDenied));
    }

    #[test]
    fn export_without_mse_is_not_allowed() {
        let (mut fs, mut rng, mut st) = setup();
        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::NotAllowed));
    }

    #[test]
    fn load_rejects_tampered_blob() {
        let (mut fs, mut rng, mut st) = setup();
        let host = handshake(&mut fs, &mut rng, &mut st);
        let nonce = [0x07u8; 12];
        let mut buf = [0x33u8; 32];
        let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut buf);
        let mut blob = [0u8; BLOB_LEN];
        blob[..12].copy_from_slice(&nonce);
        blob[12..44].copy_from_slice(&buf);
        blob[44..].copy_from_slice(&tag);
        blob[20] ^= 0xFF; // flip a ciphertext byte

        let mut req = [0u8; 128];
        let n = load_req(&mut req, &blob);
        let mut out = [0u8; 16];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::IntegrityFailure));
    }

    #[test]
    fn export_with_pin_requires_token() {
        let (mut fs, mut rng, mut st) = setup();
        fs.put(EF_PIN, &[8, 4, 1]).unwrap(); // PIN present → token required
        let _ = handshake(&mut fs, &mut rng, &mut st);
        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::PuatRequired));
    }

    #[test]
    fn backup_state_reports_flags() {
        let (mut fs, mut rng, mut st) = setup();
        assert_eq!(
            state_flags(&mut fs, &mut rng, &mut st),
            (false, true, false, false) // not sealed, has seed, not locked, not unlocked
        );
    }

    // ---- soft-lock ----

    /// Read BACKUP_STATE and return `(sealed, has_seed, locked, unlocked)`.
    fn state_flags(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        st: &mut FidoState,
    ) -> (bool, bool, bool, bool) {
        let mut req = [0u8; 16];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_STATE);
        let mut out = [0u8; 64];
        let r = call(fs, rng, st, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(4));
        let mut flags = [false; 4];
        for f in flags.iter_mut() {
            d.u8().unwrap();
            *f = d.bool().unwrap();
        }
        (flags[0], flags[1], flags[2], flags[3])
    }

    /// Host side of the channel: wrap 32 bytes as nonce ‖ ct ‖ tag.
    fn host_wrap(host: &Host, key: &[u8; 32], nonce: &[u8; 12]) -> [u8; LOCK_BLOB_LEN] {
        let mut ct = *key;
        let tag = chacha20poly1305_encrypt(&host.key, nonce, &host.aad, &mut ct);
        let mut blob = [0u8; LOCK_BLOB_LEN];
        blob[..12].copy_from_slice(nonce);
        blob[12..44].copy_from_slice(&ct);
        blob[44..].copy_from_slice(&tag);
        blob
    }

    const ACFG_TOKEN: [u8; 32] = [0x77; 32];

    /// Arm an acfg-permission pinUvAuthToken on `st` (authenticatorConfig always
    /// demands one) without disturbing the MSE channel fields.
    fn arm_acfg(st: &mut FidoState) {
        st.paut.token = ACFG_TOKEN;
        st.paut.permissions = PERM_ACFG;
        st.begin_using_token(false);
    }

    /// Build a MAC'd `authenticatorConfig` vendor request
    /// `{1: 0xFF, 2: {1: vendor_id, 2: param?}, 3: 2, 4: mac}`.
    fn config_vendor_req(vendor_id: u64, param: Option<&[u8]>, buf: &mut [u8]) -> usize {
        use rsk_crypto::pinproto;

        let mut sub = [0u8; 128];
        let sub_len = {
            let mut e = Encoder::new(Cursor::new(&mut sub[..]));
            match param {
                Some(p) => {
                    e.map(2).unwrap();
                    e.u8(1).unwrap().u64(vendor_id).unwrap();
                    e.u8(2).unwrap().bytes(p).unwrap();
                }
                None => {
                    e.map(1).unwrap();
                    e.u8(1).unwrap().u64(vendor_id).unwrap();
                }
            }
            e.writer().position()
        };

        let mut vp = [0u8; 32 + 2 + 128];
        vp[..32].fill(0xff);
        vp[32] = crate::consts::CTAP_CONFIG;
        vp[33] = 0xFF;
        vp[34..34 + sub_len].copy_from_slice(&sub[..sub_len]);
        let mut mac = [0u8; 32];
        let mlen =
            pinproto::authenticate(PinProto::Two, &ACFG_TOKEN, &vp[..34 + sub_len], &mut mac)
                .unwrap();

        // Assemble by hand — the raw subCommandParams bytes are spliced verbatim.
        let mut n = 0;
        buf[n] = 0xA4; // map(4)
        n += 1;
        buf[n..n + 3].copy_from_slice(&[0x01, 0x18, 0xFF]); // 1: 0xFF
        n += 3;
        buf[n] = 0x02; // 2: subCommandParams
        n += 1;
        buf[n..n + sub_len].copy_from_slice(&sub[..sub_len]);
        n += sub_len;
        buf[n..n + 2].copy_from_slice(&[0x03, 0x02]); // 3: protocol 2
        n += 2;
        buf[n..n + 3].copy_from_slice(&[0x04, 0x58, mlen as u8]); // 4: mac
        n += 3;
        buf[n..n + mlen].copy_from_slice(&mac[..mlen]);
        n + mlen
    }

    fn run_config(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        st: &mut FidoState,
        presence: &mut dyn UserPresence,
        req: &[u8],
    ) -> CtapResult {
        let mut out = [0u8; 64];
        let mut ctx = Ctx {
            dev: dev(),
            fs,
            rng,
            state: st,
            now_ms: 0,
            presence,
        };
        crate::config::authenticator_config(&mut ctx, req, &mut out)
    }

    /// Drive a vendor UNLOCK with `lock_key` wrapped for the current channel.
    fn run_unlock(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        st: &mut FidoState,
        lock_key: &[u8; 32],
        host: &Host,
        nonce_seed: u8,
    ) -> CtapResult {
        let blob = host_wrap(host, lock_key, &[nonce_seed; 12]);
        let mut req = [0u8; 128];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut req[..]));
            e.map(2).unwrap();
            e.u8(1).unwrap().u64(VENDOR_UNLOCK).unwrap();
            e.u8(2).unwrap().map(1).unwrap().u8(1).unwrap();
            e.bytes(&blob).unwrap();
            e.writer().position()
        };
        let mut out = [0u8; 16];
        call(fs, rng, st, &mut AlwaysConfirm, &req[..n], &mut out)
    }

    const LOCK_KEY: [u8; 32] = [0xA7; 32];

    /// setup + handshake + armed token + AUT_ENABLE; returns the original seed
    /// and the live channel.
    fn locked_setup() -> (Fs<RamStorage>, SeqRng, FidoState, Host, [u8; 32]) {
        let (mut fs, mut rng, mut st) = setup();
        let seed = load_keydev(&dev(), &mut fs).unwrap();
        let host = handshake(&mut fs, &mut rng, &mut st);
        arm_acfg(&mut st);
        let blob = host_wrap(&host, &LOCK_KEY, &[0x11; 12]);
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
        run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]).unwrap();
        (fs, rng, st, host, seed)
    }

    #[test]
    fn lock_enable_wraps_seed_and_drops_plain() {
        let (mut fs, mut rng, mut st, _host, _seed) = locked_setup();
        assert!(!fs.has_data(EF_KEY_DEV.get()));
        assert_eq!(fs.size(EF_KEY_DEV_ENC.get()), Some(LOCK_BLOB_LEN));
        // No RAM copy after enable — operations are locked out immediately.
        assert!(st.keydev_dec.is_none());
        assert_eq!(load_keydev(&dev(), &mut fs), None);
        assert_eq!(
            state_flags(&mut fs, &mut rng, &mut st),
            (false, false, true, false)
        );
    }

    #[test]
    fn unlock_restores_operations_for_the_session() {
        let (mut fs, mut rng, mut st, host, seed) = locked_setup();
        run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x22).unwrap();
        assert_eq!(st.keydev_dec, Some(seed));
        // The op-level loader sees the RAM copy; flash stays wrapped.
        let mut presence = AlwaysConfirm;
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut st,
            now_ms: 0,
            presence: &mut presence,
        };
        assert_eq!(ctx.load_keydev(), Some(seed));
        assert!(!fs.has_data(EF_KEY_DEV.get()));
        assert_eq!(
            state_flags(&mut fs, &mut rng, &mut st),
            (false, false, true, true)
        );
    }

    #[test]
    fn unlock_with_wrong_key_fails() {
        let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
        let e = run_unlock(&mut fs, &mut rng, &mut st, &[0x5C; 32], &host, 0x23);
        assert_eq!(e, Err(CtapError::InvalidParameter));
        assert!(st.keydev_dec.is_none());
    }

    #[test]
    fn unlock_when_not_locked_is_integrity_failure() {
        let (mut fs, mut rng, mut st) = setup();
        let host = handshake(&mut fs, &mut rng, &mut st);
        let e = run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x24);
        assert_eq!(e, Err(CtapError::IntegrityFailure));
    }

    #[test]
    fn disable_restores_plain_seed() {
        let (mut fs, mut rng, mut st, host, seed) = locked_setup();
        run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x25).unwrap();
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_DISABLE, None, &mut req);
        run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]).unwrap();
        assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
        assert!(st.keydev_dec.is_none()); // no stale RAM copy
        assert_eq!(load_keydev(&dev(), &mut fs), Some(seed));
        assert_eq!(
            state_flags(&mut fs, &mut rng, &mut st),
            (false, true, false, false)
        );
    }

    #[test]
    fn disable_without_unlock_is_pin_auth_invalid() {
        let (mut fs, mut rng, mut st, _host, _seed) = locked_setup();
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_DISABLE, None, &mut req);
        let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
        assert_eq!(e, Err(CtapError::PinAuthInvalid));
        assert!(fs.has_data(EF_KEY_DEV_ENC.get()));
    }

    #[test]
    fn enable_twice_is_not_allowed() {
        let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
        let blob = host_wrap(&host, &LOCK_KEY, &[0x33; 12]);
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
        let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
        assert_eq!(e, Err(CtapError::NotAllowed));
    }

    #[test]
    fn enable_without_mse_is_not_allowed() {
        let (mut fs, mut rng, mut st) = setup();
        arm_acfg(&mut st);
        let blob = [0u8; LOCK_BLOB_LEN];
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
        let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
        assert_eq!(e, Err(CtapError::NotAllowed));
        assert!(fs.has_data(EF_KEY_DEV.get()));
    }

    #[test]
    fn enable_without_touch_changes_nothing() {
        let (mut fs, mut rng, mut st) = setup();
        let host = handshake(&mut fs, &mut rng, &mut st);
        arm_acfg(&mut st);
        let blob = host_wrap(&host, &LOCK_KEY, &[0x44; 12]);
        let mut req = [0u8; 192];
        let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
        let e = run_config(&mut fs, &mut rng, &mut st, &mut Decline, &req[..n]);
        assert_eq!(e, Err(CtapError::OperationDenied));
        assert!(fs.has_data(EF_KEY_DEV.get()));
        assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
    }

    #[test]
    fn unknown_vendor_id_is_invalid_subcommand() {
        let (mut fs, mut rng, mut st) = setup();
        arm_acfg(&mut st);
        let mut req = [0u8; 192];
        let n = config_vendor_req(0xDEAD_BEEF, None, &mut req);
        let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
        assert_eq!(e, Err(CtapError::InvalidSubcommand));
    }

    #[test]
    fn backup_load_refused_while_locked() {
        let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
        let blob = host_wrap(&host, &[0x66; 32], &[0x55; 12]);
        let mut req = [0u8; 128];
        let n = load_req(&mut req, &blob);
        let mut out = [0u8; 16];
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(e, Err(CtapError::NotAllowed));
    }

    #[test]
    fn backup_export_serves_the_unlocked_ram_copy() {
        let (mut fs, mut rng, mut st, host, seed) = locked_setup();
        run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x26).unwrap();
        let mut req = [0u8; 32];
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        let mut out = [0u8; 128];
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..r]);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.u8().unwrap(), 1);
        let blob = d.bytes().unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[..12]);
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&blob[44..]);
        chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, seed);
    }

    #[test]
    fn reset_clears_the_lock_and_regenerates() {
        let (mut fs, mut rng, mut st, _host, old_seed) = locked_setup();
        let mut presence = AlwaysConfirm;
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut st,
            now_ms: 0,
            presence: &mut presence,
        };
        crate::reset::reset(&mut ctx).unwrap();
        assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
        let new_seed = load_keydev(&dev(), &mut fs).unwrap();
        assert_ne!(new_seed, old_seed); // fresh identity — the recovery path
    }

    #[test]
    fn ensure_seed_does_not_regenerate_under_lock() {
        let (mut fs, mut rng, mut st, host, seed) = locked_setup();
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        assert!(!fs.has_data(EF_KEY_DEV.get())); // boot on a locked device: no regen
        run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x27).unwrap();
        assert_eq!(st.keydev_dec, Some(seed)); // blob untouched, same seed
    }
}
