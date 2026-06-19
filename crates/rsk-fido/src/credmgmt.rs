// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorCredentialManagement`: getCredsMetadata (0x01), enumerateRPs
//! Begin/Next (0x02/0x03), enumerateCredentials Begin/Next (0x04/0x05),
//! deleteCredential (0x06) and updateUserInformation (0x07). Every subcommand
//! except the `Next` walkers is gated on a `pinUvAuthParam` carrying the `cm`
//! permission; the MAC covers the subcommand byte for 0x01/0x02 and
//! `subcommand ‖ <raw subCommandParams>` for 0x04/0x06/0x07.
//! enumerateCredentials emits the core 0x06–0x09 plus the extension fields
//! 0x0A credProtect / 0x0B largeBlobKey (derived) / 0x0C thirdPartyPayment.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::pinproto::PinProto;
use rsk_fs::Storage;

use crate::cbordec::{cbor, def_arr, def_map};
use crate::consts::{
    CM_DELETE_CREDENTIAL, CM_ENUMERATE_CREDS_BEGIN, CM_ENUMERATE_CREDS_NEXT,
    CM_ENUMERATE_RPS_BEGIN, CM_ENUMERATE_RPS_NEXT, CM_GET_CREDS_METADATA, CM_UPDATE_USER_INFO,
    EF_CRED, EF_RP, MAX_RESIDENT_CREDENTIALS,
};
use crate::credential::{
    CRED_RESIDENT_LEN, CredInput, RECORD_PREFIX, RP_PREFIX, credential_create, credential_load,
    credential_store, derive_large_blob_key, slot_map, unseal_rp_id,
};
use crate::ec::CredKey;
use crate::error::{CtapError, CtapResult};
use crate::keyderiv::fido_load_key;
use crate::state::{FidoState, PERM_CM};
use crate::{Ctx, Rng};

const MAX_RAW_SUBPARA: usize = 256;
// EF_RP record: `count(1) ‖ rpIdHash(32) ‖ box(rpId_text)` — the rpId domain is
// boxed under the device seed (see `credential::seal_rp_id`); `RP_PREFIX` spans
// the cleartext `count ‖ rpIdHash` head.

struct Req<'a> {
    subcommand: u64,
    raw_subpara: &'a [u8],
    proto: u64,
    param: Option<&'a [u8]>,
    rp_id_hash: Option<&'a [u8]>,
    cred_id: Option<&'a [u8]>,
    user_id: Option<&'a [u8]>,
    user_name: &'a str,
    user_display_name: &'a str,
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        subcommand: 0,
        raw_subpara: &[],
        proto: 0,
        param: None,
        rp_id_hash: None,
        cred_id: None,
        user_id: None,
        user_name: "",
        user_display_name: "",
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Key 1 (subCommand) is mandatory and first; keys ascend (canonical CBOR).
        if expected <= 1 && key != 1 {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => parse_subpara(data, &mut d, &mut req)?,
            3 => req.proto = cbor(d.u32())? as u64,
            4 => req.param = Some(cbor(d.bytes())?),
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Parse field 2 (subCommandParams) and capture its raw CBOR bytes (covered by
/// the pinUvAuthParam MAC).
fn parse_subpara<'a>(
    data: &'a [u8],
    d: &mut Decoder<'a>,
    req: &mut Req<'a>,
) -> Result<(), CtapError> {
    let start = d.position();
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.u32())? as u64 {
            0x01 => req.rp_id_hash = Some(cbor(d.bytes())?),
            0x02 => {
                let im = def_map(d)?;
                for _ in 0..im {
                    match cbor(d.str())? {
                        "id" => req.cred_id = Some(cbor(d.bytes())?),
                        "transports" => {
                            let a = def_arr(d)?;
                            for _ in 0..a {
                                cbor(d.str())?;
                            }
                        }
                        _ => cbor(d.skip())?, // "type"
                    }
                }
            }
            0x03 => {
                let im = def_map(d)?;
                for _ in 0..im {
                    match cbor(d.str())? {
                        "id" => req.user_id = Some(cbor(d.bytes())?),
                        "name" => req.user_name = cbor(d.str())?,
                        "displayName" => req.user_display_name = cbor(d.str())?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            _ => cbor(d.skip())?,
        }
    }
    req.raw_subpara = &data[start..d.position()];
    Ok(())
}

/// `authenticatorCredentialManagement`: write the response CBOR into `out`,
/// returning its length.
pub fn cred_mgmt<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;

    // The Next walkers reuse saved state and carry no pinUvAuthParam.
    match req.subcommand {
        CM_ENUMERATE_RPS_NEXT => return enumerate_rps(ctx, false, out),
        CM_ENUMERATE_CREDS_NEXT => {
            let rp_id_hash = ctx.state.cm.rp_id_hash;
            return enumerate_creds(ctx, false, &rp_id_hash, out);
        }
        _ => {}
    }

    // Every other subcommand requires a verified pinUvAuthParam.
    let param = req.param.ok_or(CtapError::PuatRequired)?;
    if req.proto != 1 && req.proto != 2 {
        return Err(CtapError::InvalidParameter);
    }
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;

    match req.subcommand {
        CM_GET_CREDS_METADATA => {
            verify_cm(
                ctx.state,
                proto,
                &[CM_GET_CREDS_METADATA as u8],
                param,
                None,
            )?;
            creds_metadata(ctx, out)
        }
        CM_ENUMERATE_RPS_BEGIN => {
            verify_cm(
                ctx.state,
                proto,
                &[CM_ENUMERATE_RPS_BEGIN as u8],
                param,
                None,
            )?;
            enumerate_rps(ctx, true, out)
        }
        CM_ENUMERATE_CREDS_BEGIN => {
            let h = req
                .rp_id_hash
                .filter(|h| h.len() == 32)
                .ok_or(CtapError::MissingParameter)?;
            let mut rp_id_hash = [0u8; 32];
            rp_id_hash.copy_from_slice(h);
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload =
                payload_with_subpara(CM_ENUMERATE_CREDS_BEGIN, req.raw_subpara, &mut pbuf)?;
            verify_cm(ctx.state, proto, payload, param, Some(&rp_id_hash))?;
            enumerate_creds(ctx, true, &rp_id_hash, out)
        }
        CM_DELETE_CREDENTIAL => {
            let cred_id = req.cred_id.ok_or(CtapError::MissingParameter)?;
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload = payload_with_subpara(CM_DELETE_CREDENTIAL, req.raw_subpara, &mut pbuf)?;
            verify_cm(ctx.state, proto, payload, param, None)?;
            delete_credential(ctx, cred_id)
        }
        CM_UPDATE_USER_INFO => {
            let cred_id = req.cred_id.ok_or(CtapError::MissingParameter)?;
            let user_id = req.user_id.ok_or(CtapError::MissingParameter)?;
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload = payload_with_subpara(CM_UPDATE_USER_INFO, req.raw_subpara, &mut pbuf)?;
            verify_cm(ctx.state, proto, payload, param, None)?;
            update_user(ctx, cred_id, user_id, req.user_name, req.user_display_name)
        }
        _ => Err(CtapError::InvalidParameter),
    }
}

/// Verify the pinUvAuthParam over `payload` and check the `cm` permission and
/// rpId binding.
fn verify_cm(
    state: &FidoState,
    proto: PinProto,
    payload: &[u8],
    param: &[u8],
    rp_id_hash: Option<&[u8; 32]>,
) -> Result<(), CtapError> {
    if !state.verify_token(proto, payload, param) || state.paut.permissions & PERM_CM == 0 {
        return Err(CtapError::PinAuthInvalid);
    }
    // An rpId-bound token may only manage that rp (0x01/0x02/0x06/0x07 carry no
    // rpId, so a bound token is rejected outright).
    if state.paut.has_rp_id {
        match rp_id_hash {
            Some(h) if state.paut.rp_id_hash == *h => {}
            _ => return Err(CtapError::PinAuthInvalid),
        }
    }
    Ok(())
}

/// Build `subcommand ‖ raw_subpara` for the MAC payload.
fn payload_with_subpara<'a>(
    subcmd: u64,
    raw: &[u8],
    buf: &'a mut [u8],
) -> Result<&'a [u8], CtapError> {
    if 1 + raw.len() > buf.len() {
        return Err(CtapError::RequestTooLarge);
    }
    buf[0] = subcmd as u8;
    buf[1..1 + raw.len()].copy_from_slice(raw);
    Ok(&buf[..1 + raw.len()])
}

/// 0x01 getCredsMetadata: count populated EF_CRED slots.
fn creds_metadata<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    let existing = occupied.iter().filter(|&&b| b).count() as u16;
    let remaining = MAX_RESIDENT_CREDENTIALS - existing;
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(2)
        .and_then(|e| e.u8(1)?.u16(existing))
        .and_then(|e| e.u8(2)?.u16(remaining))
        .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

/// 0x02 enumerateRPsBegin / 0x03 getNextRP: walk EF_RP records with a non-zero
/// credential count and return the `rp_counter`-th.
fn enumerate_rps<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    begin: bool,
    out: &mut [u8],
) -> CtapResult {
    if begin {
        ctx.state.cm.rp_counter = 1;
        ctx.state.cm.rp_total = 0;
    } else if ctx.state.cm.rp_counter > ctx.state.cm.rp_total {
        return Err(CtapError::NotAllowed);
    }
    let target = ctx.state.cm.rp_counter;

    let mut skip = 0u8;
    let mut total = 0u8;
    let mut found = false;
    let mut rp = [0u8; 256];
    let mut rp_len = 0usize;
    let mut buf = [0u8; 256];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_RP, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = ctx.fs.read(EF_RP + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RP_PREFIX && buf[0] > 0 {
            skip = skip.saturating_add(1);
            if skip == target && !found {
                found = true;
                rp[..n].copy_from_slice(&buf[..n]);
                rp_len = n;
                if !begin {
                    break;
                }
            }
            if begin {
                total = total.saturating_add(1);
            }
        }
    }
    if !found {
        return Err(CtapError::NoCredentials);
    }
    if begin {
        ctx.state.cm.rp_total = total;
    }
    ctx.state.cm.rp_counter = target.saturating_add(1);

    // The EF_RP tail is boxed under the device seed — recover the rpId domain.
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&rp[1..RP_PREFIX]);
    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let mut scratch = [0u8; 256];
    let unsealed = unseal_rp_id(&seed, &rp_id_hash, &rp[RP_PREFIX..rp_len], &mut scratch);
    seed.zeroize();
    let (rp_id, _) = unsealed.ok_or(CtapError::Other)?;

    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(if begin { 3 } else { 2 })
        .and_then(|e| e.u8(3)?.map(1))
        .and_then(|e| e.str("id")?.str(rp_id))
        .and_then(|e| e.u8(4)?.bytes(&rp_id_hash))
        .map_err(|_| CtapError::Other)?;
    if begin {
        enc.u8(5)
            .and_then(|e| e.u8(total))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// 0x04 enumerateCredentialsBegin / 0x05 getNextCredential: walk EF_CRED records
/// for `rp_id_hash` and return the `cred_counter`-th credential.
fn enumerate_creds<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    begin: bool,
    rp_id_hash: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    if begin {
        ctx.state.cm.cred_counter = 1;
        ctx.state.cm.cred_total = 0;
    } else if ctx.state.cm.cred_counter > ctx.state.cm.cred_total {
        return Err(CtapError::NotAllowed);
    }
    let target = ctx.state.cm.cred_counter;

    let mut skip = 0u8;
    let mut total = 0u8;
    let mut found = false;
    let mut rec = [0u8; 1024];
    let mut rec_len = 0usize;
    let mut buf = [0u8; 1024];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = ctx.fs.read(EF_CRED + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RECORD_PREFIX && buf[..32] == *rp_id_hash {
            skip = skip.saturating_add(1);
            if skip == target && !found {
                found = true;
                rec[..n].copy_from_slice(&buf[..n]);
                rec_len = n;
                if !begin {
                    break;
                }
            }
            if begin {
                total = total.saturating_add(1);
            }
        }
    }
    if !found {
        return Err(CtapError::NoCredentials);
    }

    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let result = enumerate_creds_response(&rec[..rec_len], rp_id_hash, begin, total, &seed, out);
    seed.zeroize();
    let resp_len = result?;

    if begin {
        ctx.state.cm.cred_total = total;
        ctx.state.cm.rp_id_hash = *rp_id_hash;
    }
    ctx.state.cm.cred_counter = target.saturating_add(1);
    Ok(resp_len)
}

fn enumerate_creds_response(
    rec: &[u8],
    rp_id_hash: &[u8; 32],
    begin: bool,
    total: u8,
    seed: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    let resident_id = &rec[32..RECORD_PREFIX];
    let cred_box = &rec[RECORD_PREFIX..];

    let mut scratch = [0u8; 1024];
    let cred =
        credential_load(seed, cred_box, rp_id_hash, &mut scratch).ok_or(CtapError::NotAllowed)?;

    let mut raw = fido_load_key(seed, cred_box).ok_or(CtapError::NotAllowed)?;
    let key = CredKey::from_raw(cred.curve, &raw).ok_or(CtapError::NotAllowed)?;
    raw.zeroize();

    let user_fields = u64::from(!cred.user_id.is_empty())
        + u64::from(!cred.user_name.is_empty())
        + u64::from(!cred.user_display_name.is_empty());

    // Extension response fields: 0x0A credProtect (when set), 0x0B largeBlobKey
    // (derived, when the credential opted in), 0x0C thirdPartyPayment (always).
    let large_blob_key = if cred.ext.large_blob_key {
        Some(derive_large_blob_key(seed, cred_box))
    } else {
        None
    };
    let fields = 3
        + u64::from(begin)
        + u64::from(cred.ext.cred_protect > 0)
        + u64::from(large_blob_key.is_some())
        + 1; // 0x0C thirdPartyPayment

    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(fields).map_err(|_| CtapError::Other)?;

    // 0x06 user — only the present sub-fields.
    enc.u8(6)
        .and_then(|e| e.map(user_fields))
        .map_err(|_| CtapError::Other)?;
    if !cred.user_id.is_empty() {
        enc.str("id")
            .and_then(|e| e.bytes(cred.user_id))
            .map_err(|_| CtapError::Other)?;
    }
    if !cred.user_name.is_empty() {
        enc.str("name")
            .and_then(|e| e.str(cred.user_name))
            .map_err(|_| CtapError::Other)?;
    }
    if !cred.user_display_name.is_empty() {
        enc.str("displayName")
            .and_then(|e| e.str(cred.user_display_name))
            .map_err(|_| CtapError::Other)?;
    }

    // 0x07 credentialId, 0x08 publicKey.
    enc.u8(7)
        .and_then(|e| e.map(2))
        .and_then(|e| e.str("id")?.bytes(resident_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .map_err(|_| CtapError::Other)?;
    enc.u8(8).map_err(|_| CtapError::Other)?;
    key.cose_public(&mut enc).map_err(|_| CtapError::Other)?;

    // 0x09 totalCredentials — Begin only.
    if begin {
        enc.u8(9)
            .and_then(|e| e.u8(total))
            .map_err(|_| CtapError::Other)?;
    }

    // 0x0A credProtect, 0x0B largeBlobKey, 0x0C thirdPartyPayment.
    if cred.ext.cred_protect > 0 {
        enc.u8(0x0A)
            .and_then(|e| e.u64(cred.ext.cred_protect))
            .map_err(|_| CtapError::Other)?;
    }
    if let Some(k) = large_blob_key {
        enc.u8(0x0B)
            .and_then(|e| e.bytes(&k))
            .map_err(|_| CtapError::Other)?;
    }
    enc.u8(0x0C)
        .and_then(|e| e.bool(cred.ext.third_party_payment))
        .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

/// 0x06 deleteCredential: remove the EF_CRED record with this resident id and
/// decrement (or delete) its EF_RP record. Replies with only the status byte.
fn delete_credential<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, cred_id: &[u8]) -> CtapResult {
    if cred_id.len() != CRED_RESIDENT_LEN {
        return Err(CtapError::NoCredentials);
    }
    let mut buf = [0u8; 1024];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = ctx.fs.read(EF_CRED + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RECORD_PREFIX && buf[32..RECORD_PREFIX] == *cred_id {
            let mut rp_id_hash = [0u8; 32];
            rp_id_hash.copy_from_slice(&buf[..32]);
            ctx.fs
                .delete(EF_CRED + i)
                .map_err(|_| CtapError::NotAllowed)?;
            decrement_rp(ctx, &rp_id_hash)?;
            return Ok(0);
        }
    }
    Err(CtapError::NoCredentials)
}

fn decrement_rp<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    rp_id_hash: &[u8; 32],
) -> Result<(), CtapError> {
    let mut rp = [0u8; 256];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_RP, &mut occupied);
    for j in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[j as usize] {
            continue;
        }
        let Some(m) = ctx.fs.read(EF_RP + j, &mut rp) else {
            continue;
        };
        let m = m.min(rp.len());
        if m >= RP_PREFIX && rp[1..RP_PREFIX] == *rp_id_hash {
            rp[0] = rp[0].saturating_sub(1);
            if rp[0] == 0 {
                let _ = ctx.fs.delete(EF_RP + j);
            } else {
                ctx.fs
                    .put(EF_RP + j, &rp[..m])
                    .map_err(|_| CtapError::NotAllowed)?;
            }
            break;
        }
    }
    Ok(())
}

/// 0x07 updateUserInformation: reseal the credential with a new user name /
/// display name (same rp + user id). Replies with only the status byte.
///
/// Quirk: resealing draws a fresh IV, so the credential box — and hence its
/// derived resident id — changes, staling the platform's stored credentialId.
fn update_user<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    cred_id: &[u8],
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> CtapResult {
    if cred_id.len() != CRED_RESIDENT_LEN {
        return Err(CtapError::NoCredentials);
    }
    let mut buf = [0u8; 1024];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = ctx.fs.read(EF_CRED + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RECORD_PREFIX && buf[32..RECORD_PREFIX] == *cred_id {
            let mut rp_id_hash = [0u8; 32];
            rp_id_hash.copy_from_slice(&buf[..32]);
            let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
            let r = reseal_user(
                ctx,
                &buf[RECORD_PREFIX..n],
                &rp_id_hash,
                user_id,
                user_name,
                user_display_name,
                &seed,
            );
            seed.zeroize();
            return r;
        }
    }
    Err(CtapError::NoCredentials)
}

#[allow(clippy::too_many_arguments)]
fn reseal_user<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    cred_box: &[u8],
    rp_id_hash: &[u8; 32],
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
    seed: &[u8; 32],
) -> CtapResult {
    let mut scratch = [0u8; 1024];
    let cred =
        credential_load(seed, cred_box, rp_id_hash, &mut scratch).ok_or(CtapError::NotAllowed)?;
    // The supplied user id must match the credential's (MIN-length compare).
    let cmp = user_id.len().min(cred.user_id.len());
    if user_id[..cmp] != cred.user_id[..cmp] {
        return Err(CtapError::InvalidParameter);
    }

    let mut iv = [0u8; 12];
    ctx.rng.fill(&mut iv);
    let input = CredInput {
        rp_id: cred.rp_id,
        user_id: cred.user_id,
        user_name,
        user_display_name,
        use_sign_count: cred.use_sign_count,
        rk: cred.rk,
        created_ms: ctx.now_ms,
        alg: cred.alg,
        curve: cred.curve,
        ext: cred.ext,
    };
    let mut new_box = [0u8; 512];
    let len = credential_create(seed, &ctx.dev, &input, rp_id_hash, &iv, &mut new_box)
        .map_err(|_| CtapError::NotAllowed)?;
    // Same (rp, user id) → credential_store overwrites the existing slot.
    credential_store(
        seed,
        &ctx.dev,
        ctx.fs,
        &new_box[..len],
        rp_id_hash,
        cred.rp_id,
        cred.user_id,
    )
    .map_err(|_| CtapError::NotAllowed)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FidoState;
    use crate::consts::ALG_ES256;
    use crate::makecredential::make_credential;
    use crate::seed::ensure_seed;
    use minicbor::Encoder;
    use minicbor::encode::write::Cursor;
    use rsk_crypto::{Device, pinproto, sha256};
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

    const CDH: [u8; 32] = [0xCD; 32];
    const TOKEN: [u8; 32] = [0x99; 32];

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn armed(perms: u8) -> FidoState {
        let mut s = FidoState::new();
        s.paut.token = TOKEN;
        s.paut.permissions = perms;
        s.begin_using_token(false);
        s
    }

    // A resident makeCredential request for (rp_id, user_id, name).
    fn mc_request(rp_id: &str, uid: &[u8], name: &str) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str(rp_id)
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(uid).unwrap();
            e.str("name").unwrap().str(name).unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // Register a resident credential, returning its (resident_id, pubkey x, y).
    fn register(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        rp_id: &str,
        uid: &[u8],
        name: &str,
    ) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
        let mut out = [0u8; 1024];
        let mut state = FidoState::new();
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs,
                rng,
                state: &mut state,
                now_ms: 10,
            };
            make_credential(&mut ctx, &mc_request(rp_id, uid, name), &mut out).unwrap()
        };
        parse_mc(&out[..n])
    }

    // Pull (resident credId, pubkey x, y) out of a makeCredential response.
    fn parse_mc(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
        let mut d = Decoder::new(resp);
        d.map().unwrap();
        d.u8().unwrap();
        d.str().unwrap(); // 1: "packed"
        d.u8().unwrap(); // 2
        let ad = d.bytes().unwrap();
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + cred_len].to_vec();
        let mut cd = Decoder::new(&ad[55 + cred_len..]);
        cd.map().unwrap();
        cd.u8().unwrap();
        cd.u8().unwrap();
        cd.u8().unwrap();
        cd.i64().unwrap();
        cd.i8().unwrap();
        cd.u8().unwrap();
        cd.i8().unwrap();
        let mut x = [0u8; 32];
        x.copy_from_slice(cd.bytes().unwrap());
        cd.i8().unwrap();
        let mut y = [0u8; 32];
        y.copy_from_slice(cd.bytes().unwrap());
        (cred_id, x, y)
    }

    fn setup() -> (Fs<RamStorage>, SeqRng) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        (fs, rng)
    }

    // Encode a subCommandParams map, returning its raw CBOR bytes.
    fn subpara_rpidhash(rp_hash: &[u8; 32]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 64];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(1).unwrap().u8(1).unwrap().bytes(rp_hash).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn subpara_cred(cred_id: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 128];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(1).unwrap().u8(2).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(cred_id).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn subpara_update(cred_id: &[u8], uid: &[u8], name: &str, dname: &str) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(2).unwrap();
            e.u8(2).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(cred_id).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(3).unwrap().map(3).unwrap();
            e.str("id").unwrap().bytes(uid).unwrap();
            e.str("name").unwrap().str(name).unwrap();
            e.str("displayName").unwrap().str(dname).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // Build a credMgmt request, MACing over `subcommand ‖ subpara` under `token`.
    fn cm_request(subcmd: u8, subpara: Option<&[u8]>, token: &[u8; 32]) -> std::vec::Vec<u8> {
        let mut payload = std::vec![subcmd];
        if let Some(sp) = subpara {
            payload.extend_from_slice(sp);
        }
        let mut mac = [0u8; 32];
        let mlen = pinproto::authenticate(PinProto::Two, token, &payload, &mut mac).unwrap();

        let mut req = std::vec::Vec::new();
        let fields = if subpara.is_some() { 4u8 } else { 3 };
        req.push(0xA0 | fields);
        req.extend_from_slice(&[0x01, subcmd]); // 1: subCommand
        if let Some(sp) = subpara {
            req.push(0x02); // 2: subCommandParams (raw)
            req.extend_from_slice(sp);
        }
        req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
        req.push(0x04); // 4: pinUvAuthParam
        req.push(0x58);
        req.push(mlen as u8);
        req.extend_from_slice(&mac[..mlen]);
        req
    }

    // A bare {1: subcommand} request for the Next walkers.
    fn cm_next(subcmd: u8) -> std::vec::Vec<u8> {
        std::vec![0xA1, 0x01, subcmd]
    }

    fn run(
        fs: &mut Fs<RamStorage>,
        state: &mut FidoState,
        req: &[u8],
        out: &mut [u8],
    ) -> CtapResult {
        let mut rng = SeqRng(7);
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng: &mut rng,
            state,
            now_ms: 100,
        };
        cred_mgmt(&mut ctx, req, out)
    }

    #[test]
    fn metadata_counts_residents() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        register(&mut fs, &mut rng, "other.com", &[2, 2], "b");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x01, None, &TOKEN),
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.u16().unwrap(), 2); // existing
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.u16().unwrap(), MAX_RESIDENT_CREDENTIALS - 2); // remaining
    }

    #[test]
    fn enumerate_rps_walks_then_not_allowed() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        register(&mut fs, &mut rng, "other.com", &[2, 2], "b");
        let mut state = armed(PERM_CM);

        // Begin → first RP + total = 2.
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x02, None, &TOKEN),
            &mut out,
        )
        .unwrap();
        let (id1, hash1, total) = parse_rp(&out[..n], true);
        assert_eq!(total, Some(2));

        // getNextRP → second RP (no total field).
        let n = run(&mut fs, &mut state, &cm_next(0x03), &mut out).unwrap();
        let (id2, hash2, total2) = parse_rp(&out[..n], false);
        assert_eq!(total2, None);
        assert_ne!(id1, id2);
        assert_eq!(hash1, sha256(id1.as_bytes()));
        assert_eq!(hash2, sha256(id2.as_bytes()));

        // Exhausted → NotAllowed.
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x03), &mut out),
            Err(CtapError::NotAllowed)
        );
    }

    fn parse_rp(resp: &[u8], begin: bool) -> (std::string::String, [u8; 32], Option<u8>) {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        assert_eq!(fields, if begin { 3 } else { 2 });
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "id");
        let id = d.str().unwrap().to_string();
        assert_eq!(d.u8().unwrap(), 4);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(d.bytes().unwrap());
        let total = if begin {
            assert_eq!(d.u8().unwrap(), 5);
            Some(d.u8().unwrap())
        } else {
            None
        };
        (id, hash, total)
    }

    #[test]
    fn enumerate_credentials_returns_matching_pubkey() {
        let (mut fs, mut rng) = setup();
        // Two creds for the same rp (distinct users), one for another rp.
        let (_id_a, xa, ya) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
        let (_id_b, xb, yb) = register(&mut fs, &mut rng, "example.com", &[2, 2], "bob");
        register(&mut fs, &mut rng, "other.com", &[3, 3], "carol");
        let rp_hash = sha256(b"example.com");
        let mut state = armed(PERM_CM);

        // Begin → first of two, total = 2, COSE key matches one of the registered keys.
        let mut out = [0u8; 512];
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
            &mut out,
        )
        .unwrap();
        let (uid1, x1, y1, total) = parse_cred(&out[..n], true);
        assert_eq!(total, Some(2));

        // getNextCredential → the other one.
        let n = run(&mut fs, &mut state, &cm_next(0x05), &mut out).unwrap();
        let (uid2, x2, y2, total2) = parse_cred(&out[..n], false);
        assert_eq!(total2, None);
        assert_ne!(uid1, uid2);

        // The two returned keys are exactly the two registered keys (in some order).
        let got = [(x1, y1), (x2, y2)];
        assert!(got.contains(&(xa, ya)));
        assert!(got.contains(&(xb, yb)));

        // Exhausted → NotAllowed.
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x05), &mut out),
            Err(CtapError::NotAllowed)
        );
    }

    fn parse_cred(resp: &[u8], begin: bool) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32], Option<u8>) {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        // 6/7/8 [+9 on Begin] + 0x0C thirdPartyPayment (always emitted).
        assert_eq!(fields, if begin { 5 } else { 4 });
        // 0x06 user
        assert_eq!(d.u8().unwrap(), 6);
        let um = d.map().unwrap().unwrap();
        let mut uid = std::vec::Vec::new();
        for _ in 0..um {
            match d.str().unwrap() {
                "id" => uid = d.bytes().unwrap().to_vec(),
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        // 0x07 credentialId
        assert_eq!(d.u8().unwrap(), 7);
        d.skip().unwrap();
        // 0x08 publicKey (COSE EC2)
        assert_eq!(d.u8().unwrap(), 8);
        assert_eq!(d.map().unwrap().unwrap(), 5);
        d.u8().unwrap();
        d.u8().unwrap();
        d.u8().unwrap();
        d.i64().unwrap();
        d.i8().unwrap();
        d.u8().unwrap();
        d.i8().unwrap();
        let mut x = [0u8; 32];
        x.copy_from_slice(d.bytes().unwrap());
        d.i8().unwrap();
        let mut y = [0u8; 32];
        y.copy_from_slice(d.bytes().unwrap());
        let total = if begin {
            assert_eq!(d.u8().unwrap(), 9);
            Some(d.u8().unwrap())
        } else {
            None
        };
        (uid, x, y, total)
    }

    #[test]
    fn enumerate_emits_extension_fields() {
        let (mut fs, mut rng) = setup();
        let rp_hash = sha256(b"example.com");

        // Register a resident credential with credProtect=3 + largeBlobKey.
        let mut buf = [0u8; 512];
        let req = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[7, 7, 7, 7]).unwrap();
            e.str("name").unwrap().str("a").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6).unwrap().map(2).unwrap();
            e.str("credProtect").unwrap().u64(3).unwrap();
            e.str("largeBlobKey").unwrap().bool(true).unwrap();
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
            e.writer().position()
        };
        let mut out = [0u8; 1024];
        {
            let mut state = FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            make_credential(&mut ctx, &buf[..req], &mut out).unwrap();
        }

        // enumerateCredentialsBegin → response carries 0x0A/0x0B/0x0C.
        let mut state = armed(PERM_CM);
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..n]);
        let fields = d.map().unwrap().unwrap();
        let (mut cp, mut lbk, mut tpp) = (None, None, None);
        for _ in 0..fields {
            match d.u8().unwrap() {
                0x0A => cp = Some(d.u64().unwrap()),
                0x0B => lbk = Some(d.bytes().unwrap().to_vec()),
                0x0C => tpp = Some(d.bool().unwrap()),
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        assert_eq!(cp, Some(3), "credProtect");
        assert_eq!(tpp, Some(false), "thirdPartyPayment always emitted");
        // 0x0B is the derived largeBlobKey of the stored credential.
        let mut rec = [0u8; 1024];
        let m = fs.read(EF_CRED, &mut rec).unwrap();
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        let expected = derive_large_blob_key(&seed, &rec[RECORD_PREFIX..m]);
        assert_eq!(lbk.as_deref(), Some(&expected[..]));
    }

    #[test]
    fn enumerate_credentials_requires_rpidhash() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        // 0x04 with no subCommandParams → MissingParameter.
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x04, None, &TOKEN),
                &mut out
            ),
            Err(CtapError::MissingParameter)
        );
    }

    #[test]
    fn delete_credential_drops_count_and_rp() {
        let (mut fs, mut rng) = setup();
        let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
        register(&mut fs, &mut rng, "example.com", &[2, 2], "bob");
        register(&mut fs, &mut rng, "other.com", &[3, 3], "carol");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];

        // Delete alice → metadata count 3 → 2, example.com RP still present (bob remains).
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x06, Some(&subpara_cred(&id_a)), &TOKEN),
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 0);
        assert_eq!(metadata_count(&mut fs, &mut state), 2);
        assert!(rp_present(&mut fs, &mut state, &sha256(b"example.com")));

        // Delete carol (sole cred for other.com) → its RP record disappears. Look
        // her up by enumerating other.com (we did not capture her id at register).
        let other = sha256(b"other.com");
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(&other)), &TOKEN),
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..n]);
        d.map().unwrap();
        d.u8().unwrap();
        d.skip().unwrap(); // user
        d.u8().unwrap(); // 7
        d.map().unwrap();
        assert_eq!(d.str().unwrap(), "id");
        let carol_id = d.bytes().unwrap().to_vec();
        run(
            &mut fs,
            &mut state,
            &cm_request(0x06, Some(&subpara_cred(&carol_id)), &TOKEN),
            &mut out,
        )
        .unwrap();
        assert!(!rp_present(&mut fs, &mut state, &other));
    }

    #[test]
    fn delete_unknown_credential_is_no_credentials() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        let bogus = [0u8; CRED_RESIDENT_LEN];
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x06, Some(&subpara_cred(&bogus)), &TOKEN),
                &mut out
            ),
            Err(CtapError::NoCredentials)
        );
    }

    #[test]
    fn update_user_changes_name() {
        let (mut fs, mut rng) = setup();
        let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 512];

        // Update alice's name (same user id).
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(
                0x07,
                Some(&subpara_update(&id_a, &[1, 1], "alice2", "Alice Two")),
                &TOKEN,
            ),
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 0);

        // Re-enumerate: still one cred for the rp, with the new name.
        let rp_hash = sha256(b"example.com");
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
            &mut out,
        )
        .unwrap();
        let name = cred_user_name(&out[..n]);
        assert_eq!(name, "alice2");
    }

    #[test]
    fn update_user_id_mismatch_rejected() {
        let (mut fs, mut rng) = setup();
        let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        // A different user id than the credential's → InvalidParameter.
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(
                    0x07,
                    Some(&subpara_update(&id_a, &[9, 9], "x", "y")),
                    &TOKEN
                ),
                &mut out
            ),
            Err(CtapError::InvalidParameter)
        );
    }

    fn cred_user_name(resp: &[u8]) -> std::string::String {
        let mut d = Decoder::new(resp);
        d.map().unwrap();
        assert_eq!(d.u8().unwrap(), 6);
        let um = d.map().unwrap().unwrap();
        let mut name = std::string::String::new();
        for _ in 0..um {
            match d.str().unwrap() {
                "name" => name = d.str().unwrap().to_string(),
                "id" => {
                    d.bytes().unwrap();
                }
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        name
    }

    fn metadata_count(fs: &mut Fs<RamStorage>, state: &mut FidoState) -> u16 {
        let mut out = [0u8; 64];
        let n = run(fs, state, &cm_request(0x01, None, &TOKEN), &mut out).unwrap();
        let mut d = Decoder::new(&out[..n]);
        d.map().unwrap();
        d.u8().unwrap();
        d.u16().unwrap()
    }

    fn rp_present(fs: &mut Fs<RamStorage>, state: &mut FidoState, rp_hash: &[u8; 32]) -> bool {
        let mut out = [0u8; 256];
        run(
            fs,
            state,
            &cm_request(0x04, Some(&subpara_rpidhash(rp_hash)), &TOKEN),
            &mut out,
        )
        .is_ok()
    }

    #[test]
    fn missing_param_is_puat_required() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 64];
        // {1: 1} — getCredsMetadata with no pinUvAuthParam.
        assert_eq!(
            run(&mut fs, &mut state, &[0xA1, 0x01, 0x01], &mut out),
            Err(CtapError::PuatRequired)
        );
    }

    #[test]
    fn bad_mac_rejected() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 64];
        // MAC under the wrong token → PinAuthInvalid.
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x01, None, &[0x11; 32]),
                &mut out
            ),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn without_cm_permission_rejected() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        // A token without the cm permission.
        let mut state = armed(crate::state::PERM_MC);
        let mut out = [0u8; 64];
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x01, None, &TOKEN),
                &mut out
            ),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn enumerate_rps_empty_is_no_credentials() {
        let (mut fs, _rng) = setup();
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 64];
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x02, None, &TOKEN),
                &mut out
            ),
            Err(CtapError::NoCredentials)
        );
    }

    #[test]
    fn get_next_without_begin_is_not_allowed() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 64];
        // getNextRP / getNextCredential with no prior Begin → NotAllowed.
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x03), &mut out),
            Err(CtapError::NotAllowed)
        );
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x05), &mut out),
            Err(CtapError::NotAllowed)
        );
    }

    // Does any live EF_RP record contain `needle` in its raw at-rest bytes?
    fn rp_flash_has(fs: &mut Fs<RamStorage>, needle: &[u8]) -> bool {
        let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
        slot_map(fs, EF_RP, &mut occupied);
        let mut buf = [0u8; 256];
        for i in 0..MAX_RESIDENT_CREDENTIALS {
            if !occupied[i as usize] {
                continue;
            }
            if let Some(n) = fs.read(EF_RP + i, &mut buf) {
                let n = n.min(buf.len());
                if buf[..n].windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn rp_domain_sealed_on_flash() {
        let (mut fs, mut rng) = setup();
        register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
        // The rpId domain must not survive in cleartext in the EF_RP record...
        assert!(
            !rp_flash_has(&mut fs, b"example.com"),
            "rpId domain leaked in cleartext on flash"
        );
        // ...but enumerateRPs still round-trips it to the host.
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x02, None, &TOKEN),
            &mut out,
        )
        .unwrap();
        let (id, hash, _) = parse_rp(&out[..n], true);
        assert_eq!(id, "example.com");
        assert_eq!(hash, sha256(b"example.com"));
    }

    #[test]
    fn legacy_plaintext_rp_migrates_and_stays_usable() {
        let (mut fs, _rng) = setup();
        // A pre-migration EF_RP record: count(1) ‖ rpIdHash(32) ‖ cleartext domain.
        let hash = sha256(b"example.com");
        let mut rec = std::vec::Vec::new();
        rec.push(1u8);
        rec.extend_from_slice(&hash);
        rec.extend_from_slice(b"example.com");
        fs.put(EF_RP, &rec).unwrap();
        assert!(rp_flash_has(&mut fs, b"example.com"));

        // Boot migration boxes the cleartext domain in place.
        crate::credential::migrate_rp_seal(&dev(), &mut fs);
        assert!(
            !rp_flash_has(&mut fs, b"example.com"),
            "migration left the rpId domain in cleartext"
        );
        // The count byte survives the re-box.
        let mut buf = [0u8; 256];
        let n = fs.read(EF_RP, &mut buf).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1..RP_PREFIX], hash[..]);

        // enumerateRPs still recovers the original domain.
        let mut state = armed(PERM_CM);
        let mut out = [0u8; 256];
        let n2 = run(
            &mut fs,
            &mut state,
            &cm_request(0x02, None, &TOKEN),
            &mut out,
        )
        .unwrap();
        let (id, h, _) = parse_rp(&out[..n2], true);
        assert_eq!(id, "example.com");
        assert_eq!(h, hash);

        // Idempotent: a second pass is a no-op and the record stays usable.
        let before = buf[..n.min(buf.len())].to_vec();
        crate::credential::migrate_rp_seal(&dev(), &mut fs);
        let m = fs.read(EF_RP, &mut buf).unwrap();
        assert_eq!(
            &buf[..m.min(buf.len())],
            &before[..],
            "migration not idempotent"
        );
    }
}
