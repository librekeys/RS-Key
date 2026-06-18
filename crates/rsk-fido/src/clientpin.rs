// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorClientPIN`: getPINRetries (1), getKeyAgreement (2), setPIN
//! (3), changePIN (4), getPinToken (5) and
//! getPinUvAuthTokenUsingPinWithPermissions (9); the PIN/UV-auth state lives in
//! [`crate::state::FidoState`]. PIN commands never touch the seed's at-rest
//! format (UP-only operations must keep working across power cycles); a
//! successful verify only migrates legacy PIN-wrapped blobs back to plain
//! ([`migrate_keydev_pin`]).

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::pinproto::{self, PinProto};
use rsk_crypto::sha256;
use rsk_fs::Storage;

use crate::cbordec::{cbor, def_map};
use crate::consts::{EF_MINPINLEN, EF_PIN, MAX_PIN_RETRIES, MIN_PIN_LENGTH};
use crate::cose::cose_key_ecdh;
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::migrate_keydev_pin;
use crate::state::{PERM_BE, PERM_GA, PERM_MC, PERM_PCMR};
use crate::{Ctx, Rng};

const PIN_FILE_LEN: usize = 35; // retries(1) + len(1) + format(1) + verifier(32)
const PADDED_PIN_LEN: usize = 64;

#[derive(Default)]
struct Req<'a> {
    proto: u64,
    subcommand: u64,
    alg: i64,
    key_agreement: bool,
    kax: &'a [u8],
    kay: &'a [u8],
    pin_uv_auth_param: Option<&'a [u8]>,
    new_pin_enc: Option<&'a [u8]>,
    pin_hash_enc: Option<&'a [u8]>,
    permissions: u64,
    rp_id: Option<&'a str>,
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req::default();
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1 (pinUvAuthProtocol) and 2 (subCommand) are mandatory and first.
        if expected <= 2 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.proto = cbor(d.u32())? as u64,
            2 => req.subcommand = cbor(d.u32())? as u64,
            3 => {
                req.key_agreement = true;
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.i32())? {
                        3 => req.alg = cbor(d.i64())?,
                        -2 => req.kax = cbor(d.bytes())?,
                        -3 => req.kay = cbor(d.bytes())?,
                        _ => cbor(d.skip())?, // kty (1), crv (-1)
                    }
                }
            }
            4 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            5 => req.new_pin_enc = Some(cbor(d.bytes())?),
            6 => req.pin_hash_enc = Some(cbor(d.bytes())?),
            9 => req.permissions = cbor(d.u32())? as u64,
            10 => req.rp_id = Some(cbor(d.str())?),
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

/// `authenticatorClientPIN`: dispatch the subcommand, writing the response CBOR
/// into `out` and returning its length (0 for set/changePIN, which reply with
/// only the status byte).
pub fn client_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;
    ctx.state.ensure_initialized(ctx.rng);

    match req.subcommand {
        0x0 => Err(CtapError::MissingParameter),
        0x1 => get_pin_retries(ctx, out),
        0x2 => get_key_agreement(ctx, &req, out),
        0x3 => set_pin(ctx, &req, out),
        0x4 => change_pin(ctx, &req, out),
        0x5 | 0x9 => get_pin_token(ctx, &req, out),
        _ => Err(CtapError::UnsupportedOption),
    }
}

fn get_pin_retries<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let retries = pin_retries(ctx);
    let pc = ctx.state.needs_power_cycle;
    let len = encode(out, |e| {
        e.map(if pc { 2 } else { 1 })?.u8(3)?.u8(retries)?;
        if pc {
            e.u8(4)?.bool(true)?;
        }
        Ok(())
    })?;
    Ok(len)
}

fn get_key_agreement<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    out: &mut [u8],
) -> CtapResult {
    if PinProto::from_u64(req.proto).is_none() {
        return Err(if req.proto == 0 {
            CtapError::MissingParameter
        } else {
            CtapError::InvalidParameter
        });
    }
    let (x, y) = ctx.state.ephemeral_public().ok_or(CtapError::Other)?;
    let len = encode(out, |e| {
        e.map(1)?.u8(1)?;
        cose_key_ecdh(e, &x, &y)
    })?;
    Ok(len)
}

fn set_pin<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    let _ = out;
    let proto = require_pin_inputs(req, true, false)?;
    if ctx.fs.has_data(EF_PIN) {
        return Err(CtapError::NotAllowed);
    }
    let new_pin_enc = req.new_pin_enc.unwrap();
    if new_pin_enc.len() != 64 + proto.iv_overhead() {
        return Err(CtapError::InvalidParameter);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let secret = &shared[..slen];

    if !pinproto::verify(proto, secret, new_pin_enc, req.pin_uv_auth_param.unwrap()) {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    let mut padded = [0u8; PADDED_PIN_LEN];
    let dec = pinproto::decrypt(proto, secret, new_pin_enc, &mut padded);
    shared.zeroize();
    if dec.is_err() {
        return Err(CtapError::PinAuthInvalid);
    }
    let res = store_new_pin(ctx, &padded);
    padded.zeroize();
    res?;
    journal::append(ctx, journal::EV_PIN_SET, 0, &[]);
    Ok(0)
}

fn change_pin<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    let _ = out;
    let proto = require_pin_inputs(req, true, true)?;
    let pin_hash_enc = req.pin_hash_enc.unwrap();
    let new_pin_enc = req.new_pin_enc.unwrap();
    pin_set_and_unblocked(ctx)?;
    if new_pin_enc.len() != 64 + proto.iv_overhead()
        || pin_hash_enc.len() != 16 + proto.iv_overhead()
    {
        return Err(CtapError::InvalidParameter);
    }
    if ctx.state.needs_power_cycle {
        return Err(CtapError::PinAuthBlocked);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let secret = &shared[..slen];

    // The MAC covers newPinEnc ‖ pinHashEnc (≤ 80 + 32 for protocol 2).
    let mut macd = [0u8; 112];
    macd[..new_pin_enc.len()].copy_from_slice(new_pin_enc);
    macd[new_pin_enc.len()..new_pin_enc.len() + pin_hash_enc.len()].copy_from_slice(pin_hash_enc);
    if !pinproto::verify(
        proto,
        secret,
        &macd[..new_pin_enc.len() + pin_hash_enc.len()],
        req.pin_uv_auth_param.unwrap(),
    ) {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }

    // Verify the old PIN (decrements the counter; mismatch path regenerates).
    let mut old_hash = [0u8; PADDED_PIN_LEN];
    if pinproto::decrypt(proto, secret, pin_hash_enc, &mut old_hash).is_err() {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    if let Err(e) = verify_pin_hash(ctx, &old_hash[..16]) {
        shared.zeroize();
        old_hash.zeroize();
        return Err(e);
    }
    // The verify migrated any legacy PIN-wrapped seed; the seed itself is
    // PIN-independent, so changing the PIN only swaps the verifier.
    old_hash.zeroize();

    // Decrypt + install the new PIN.
    let mut padded = [0u8; PADDED_PIN_LEN];
    let dec = pinproto::decrypt(proto, secret, new_pin_enc, &mut padded);
    shared.zeroize();
    if dec.is_err() {
        return Err(CtapError::PinAuthInvalid);
    }
    let res = store_new_pin(ctx, &padded);
    padded.zeroize();
    res?;
    // The new PIN met minPINLength (store_new_pin), so the change satisfies a
    // pending forced-PIN-change policy.
    clear_force_change(ctx)?;
    ctx.state.reset_pin_uv_auth_token(ctx.rng);
    ctx.state.reset_persistent_token(ctx.rng);
    ctx.state.needs_power_cycle = false;
    journal::append(ctx, journal::EV_PIN_CHANGE, 0, &[]);
    Ok(0)
}

fn get_pin_token<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    let proto = require_pin_inputs(req, false, true)?;
    let mut permissions = req.permissions as u8;
    if req.subcommand == 0x5 {
        if req.permissions != 0 || req.rp_id.is_some() {
            return Err(CtapError::InvalidParameter);
        }
    } else {
        // 0x9: getPinUvAuthTokenUsingPinWithPermissions.
        if req.permissions == 0 {
            return Err(CtapError::InvalidParameter);
        }
        if permissions & PERM_BE != 0 {
            return Err(CtapError::UnauthorizedPermission);
        }
        if permissions & PERM_PCMR != 0 && permissions != PERM_PCMR {
            return Err(CtapError::UnauthorizedPermission);
        }
    }
    pin_set_and_unblocked(ctx)?;
    if ctx.state.needs_power_cycle {
        return Err(CtapError::PinAuthBlocked);
    }
    let mut shared = [0u8; 64];
    let slen = derive_shared(ctx, req, proto, &mut shared)?;
    let secret = &shared[..slen];

    let mut pin_hash = [0u8; PADDED_PIN_LEN];
    if pinproto::decrypt(proto, secret, req.pin_hash_enc.unwrap(), &mut pin_hash).is_err() {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }
    if let Err(e) = verify_pin_hash(ctx, &pin_hash[..16]) {
        shared.zeroize();
        pin_hash.zeroize();
        return Err(e);
    }

    pin_hash.zeroize();

    // CTAP 2.1 forced PIN change: while EF_MINPINLEN[1] is set, a successful
    // PIN check still refuses the token — only changePIN lifts the flag.
    if force_change_pending(ctx) {
        return Err(CtapError::PinPolicyViolation);
    }

    // Build the token and return it encrypted under the shared secret.
    let pdata = if permissions & PERM_PCMR != 0 {
        ctx.state.ppaut_permissions = PERM_PCMR;
        ctx.state.ppaut_token
    } else {
        ctx.state.reset_pin_uv_auth_token(ctx.rng);
        ctx.state.begin_using_token(false);
        if req.subcommand == 0x5 {
            permissions = PERM_MC | PERM_GA;
        }
        ctx.state.paut.permissions = permissions;
        match req.rp_id {
            Some(rp) => {
                ctx.state.paut.rp_id_hash = sha256(rp.as_bytes());
                ctx.state.paut.has_rp_id = true;
            }
            None => ctx.state.paut.has_rp_id = false,
        }
        ctx.state.paut.token
    };

    let mut token_enc = [0u8; 32 + 16];
    let enc_len = pinproto::encrypt(proto, secret, &[0u8; 16], &pdata, &mut token_enc);
    shared.zeroize();
    let enc_len = enc_len.map_err(|_| CtapError::Other)?;
    ctx.state.needs_power_cycle = false;
    let len = encode(out, |e| {
        e.map(1)?.u8(2)?.bytes(&token_enc[..enc_len])?;
        Ok(())
    })?;
    Ok(len)
}

// --- helpers --------------------------------------------------------------

/// The retry counter from EF_PIN, or the full budget if no PIN is set.
fn pin_retries<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> u8 {
    let mut buf = [0u8; PIN_FILE_LEN];
    match ctx.fs.read(EF_PIN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MAX_PIN_RETRIES,
    }
}

fn pin_set_and_unblocked<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> Result<(), CtapError> {
    if !ctx.fs.has_data(EF_PIN) {
        return Err(CtapError::PinNotSet);
    }
    if pin_retries(ctx) == 0 {
        return Err(CtapError::PinBlocked);
    }
    Ok(())
}

/// Common presence checks for set/change/getToken; returns the protocol.
/// `need_new_pin` (set/change) also requires `pinUvAuthParam`; getPinToken carries
/// neither.
fn require_pin_inputs(
    req: &Req,
    need_new_pin: bool,
    need_pin_hash: bool,
) -> Result<PinProto, CtapError> {
    let missing = !req.key_agreement
        || req.kax.is_empty()
        || req.kay.is_empty()
        || req.proto == 0
        || req.alg == 0
        || (need_new_pin && (req.new_pin_enc.is_none() || req.pin_uv_auth_param.is_none()))
        || (need_pin_hash && req.pin_hash_enc.is_none());
    if missing {
        return Err(CtapError::MissingParameter);
    }
    PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)
}

fn derive_shared<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    proto: PinProto,
    out: &mut [u8; 64],
) -> Result<usize, CtapError> {
    let kax = coord(req.kax)?;
    let kay = coord(req.kay)?;
    pinproto::ecdh(proto, ctx.state.ephemeral_scalar(), &kax, &kay, out)
        .map_err(|_| CtapError::InvalidParameter)
}

/// Compare a candidate 16-byte PIN hash against the stored verifier. Decrements
/// the retry counter first; on mismatch applies the lockout ladder.
fn verify_pin_hash<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    pin_hash: &[u8],
) -> Result<(), CtapError> {
    let mut pin_data = [0u8; PIN_FILE_LEN];
    let n = ctx
        .fs
        .read(EF_PIN, &mut pin_data)
        .ok_or(CtapError::PinNotSet)?;
    if n != PIN_FILE_LEN {
        return Err(CtapError::Other);
    }
    pin_data[0] -= 1;
    ctx.fs
        .put(EF_PIN, &pin_data)
        .map_err(|_| CtapError::Other)?;
    // Read the decremented counter back before trusting it. This single flash
    // write is the anti-bruteforce gate; a glitch or partial program during put()
    // could persist the old (higher) count while RAM marches on, silently widening
    // the retry budget. If the stored value doesn't match, fail closed (treat as
    // blocked) rather than continue on an unverified count — the same read-back the
    // OTP fuse writes already do (firmware/src/otp_keys.rs).
    let mut readback = [0u8; PIN_FILE_LEN];
    match ctx.fs.read(EF_PIN, &mut readback) {
        Some(PIN_FILE_LEN) if readback[0] == pin_data[0] => {}
        _ => return Err(CtapError::PinBlocked),
    }
    let retries = pin_data[0];

    let cand = ctx.dev.pin_derive_verifier(pin_hash);
    let mut matched = pinproto_ct_eq(&cand, &pin_data[3..PIN_FILE_LEN]);
    if !matched && ctx.dev.otp_key.is_some() {
        // Kbase-migration fallback: a verifier stored before the OTP key was
        // provisioned. A match under the pre-OTP arm is the correct PIN — the
        // seed migrates below before the verifier is rewritten, so a crash
        // between the two re-runs this path on the next verify.
        let cand_old = ctx.dev.without_otp().pin_derive_verifier(pin_hash);
        if pinproto_ct_eq(&cand_old, &pin_data[3..PIN_FILE_LEN]) {
            pin_data[3..PIN_FILE_LEN].copy_from_slice(&cand);
            matched = true;
        }
    }
    if !matched {
        ctx.state.regenerate(ctx.rng);
        if retries == 0 {
            // The transition into the hard lockout (later attempts are turned
            // away before the verify, so this records exactly once).
            journal::append(ctx, journal::EV_PIN_LOCKOUT, 0, &[]);
            return Err(CtapError::PinBlocked);
        }
        ctx.state.new_pin_mismatches += 1;
        if ctx.state.new_pin_mismatches >= 3 {
            ctx.state.needs_power_cycle = true;
            journal::append(ctx, journal::EV_PIN_LOCKOUT, 1, &[]);
            return Err(CtapError::PinAuthBlocked);
        }
        return Err(CtapError::PinInvalid);
    }

    // Correct PIN: migrate a legacy PIN-wrapped seed to the plain format (the
    // only moment its outer layer is open), then reset the counter.
    migrate_keydev_pin(&ctx.dev, ctx.fs, pin_hash).map_err(|_| CtapError::Other)?;
    pin_data[0] = MAX_PIN_RETRIES;
    ctx.state.new_pin_mismatches = 0;
    ctx.fs
        .put(EF_PIN, &pin_data)
        .map_err(|_| CtapError::Other)?;
    Ok(())
}

/// Validate the padded new PIN and store the EF_PIN verifier. The seed is not
/// touched — it stays kbase-only so UP-only operations keep working.
fn store_new_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    padded: &[u8; 64],
) -> Result<(), CtapError> {
    if padded[PADDED_PIN_LEN - 1] != 0 {
        return Err(CtapError::PinPolicyViolation);
    }
    let pin_len = padded
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(PADDED_PIN_LEN);
    let min_pin = min_pin_length(ctx);
    if (pin_len as u8) < min_pin {
        return Err(CtapError::PinPolicyViolation);
    }
    let mut dhash = sha256(&padded[..pin_len]);
    let mut pin_data = [0u8; PIN_FILE_LEN];
    pin_data[0] = MAX_PIN_RETRIES;
    pin_data[1] = pin_len as u8;
    pin_data[2] = 1; // verifier format 1
    pin_data[3..].copy_from_slice(&ctx.dev.pin_derive_verifier(&dhash[..16]));
    dhash.zeroize();
    ctx.fs
        .put(EF_PIN, &pin_data)
        .map_err(|_| CtapError::Other)?;
    ctx.state.needs_power_cycle = false;
    Ok(())
}

fn min_pin_length<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> u8 {
    let mut buf = [0u8; 2];
    match ctx.fs.read(EF_MINPINLEN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MIN_PIN_LENGTH,
    }
}

/// The pending forced-PIN-change flag (EF_MINPINLEN[1]).
fn force_change_pending<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> bool {
    let mut buf = [0u8; 2];
    matches!(ctx.fs.read(EF_MINPINLEN, &mut buf), Some(n) if n >= 2 && buf[1] != 0)
}

/// A successful changePIN satisfies the policy: drop the flag, keep the
/// minimum and the RP-id hash list (EF_MINPINLEN = [min, force, hashes…]).
fn clear_force_change<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> Result<(), CtapError> {
    let mut buf = [0u8; 2 + 32 * 8]; // matches config's MAX_MIN_PIN_RPIDS cap
    if let Some(n) = ctx.fs.read(EF_MINPINLEN, &mut buf)
        && n >= 2
        && buf[1] != 0
    {
        buf[1] = 0;
        ctx.fs
            .put(EF_MINPINLEN, &buf[..n])
            .map_err(|_| CtapError::Other)?;
    }
    Ok(())
}

fn pinproto_ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FidoState;
    use crate::consts::EF_KEY_DEV;
    use crate::seed::{ensure_seed, load_keydev};
    use rsk_crypto::Device;
    use rsk_crypto::pinproto::public_xy;
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

    fn setup() -> (Fs<RamStorage>, SeqRng) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        (fs, rng)
    }

    fn run(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        state: &mut FidoState,
        data: &[u8],
        out: &mut [u8],
    ) -> CtapResult {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state,
            now_ms: 0,
        };
        client_pin(&mut ctx, data, out)
    }

    // A clientPIN request field value.
    enum V<'a> {
        U(u64),
        B(&'a [u8]),
        Cose(&'a [u8; 32], &'a [u8; 32]),
    }

    fn build(fields: &[(u8, V)]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 1024];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(fields.len() as u64).unwrap();
            for (k, v) in fields {
                e.u8(*k).unwrap();
                match v {
                    V::U(x) => {
                        e.u64(*x).unwrap();
                    }
                    V::B(b) => {
                        e.bytes(b).unwrap();
                    }
                    V::Cose(x, y) => cose_key_ecdh(&mut e, x, y).unwrap(),
                }
            }
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // The platform's ephemeral key + the shared secret with the authenticator.
    struct Platform {
        proto: PinProto,
        wire: u64,
        x: [u8; 32],
        y: [u8; 32],
        shared: [u8; 64],
        slen: usize,
    }

    fn key_agreement(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        state: &mut FidoState,
        proto: PinProto,
        wire: u64,
    ) -> Platform {
        let req = build(&[(1, V::U(wire)), (2, V::U(2))]);
        let mut out = [0u8; 256];
        let n = run(fs, rng, state, &req, &mut out).unwrap();
        // { 1: { 1:2, 3:-25, -1:1, -2:x, -3:y } }
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.map().unwrap().unwrap(), 5);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.i64().unwrap(), crate::consts::ALG_ECDH_ES_HKDF_256);
        assert_eq!(d.i8().unwrap(), -1);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.i8().unwrap(), -2);
        let mut ax = [0u8; 32];
        ax.copy_from_slice(d.bytes().unwrap());
        assert_eq!(d.i8().unwrap(), -3);
        let mut ay = [0u8; 32];
        ay.copy_from_slice(d.bytes().unwrap());

        // The authenticator's key must be a valid P-256 point.
        let pscalar = {
            let mut s = [0u8; 32];
            s[31] = 0x42;
            s[0] = 0x13;
            s
        };
        let (x, y) = public_xy(&pscalar).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(proto, &pscalar, &ax, &ay, &mut shared).unwrap();
        Platform {
            proto,
            wire,
            x,
            y,
            shared,
            slen,
        }
    }

    impl Platform {
        fn secret(&self) -> &[u8] {
            &self.shared[..self.slen]
        }

        // Encrypt a value with a fixed IV (deterministic test vectors).
        fn enc(&self, pt: &[u8]) -> std::vec::Vec<u8> {
            let mut out = [0u8; 96];
            let n =
                pinproto::encrypt(self.proto, self.secret(), &[0x55; 16], pt, &mut out).unwrap();
            out[..n].to_vec()
        }

        fn mac(&self, data: &[u8]) -> std::vec::Vec<u8> {
            let mut out = [0u8; 32];
            let n = pinproto::authenticate(self.proto, self.secret(), data, &mut out).unwrap();
            out[..n].to_vec()
        }

        fn set_pin_req(&self, pin: &[u8]) -> std::vec::Vec<u8> {
            let mut padded = [0u8; 64];
            padded[..pin.len()].copy_from_slice(pin);
            let npe = self.enc(&padded);
            let puap = self.mac(&npe);
            build(&[
                (1, V::U(self.wire)),
                (2, V::U(3)),
                (3, V::Cose(&self.x, &self.y)),
                (4, V::B(&puap)),
                (5, V::B(&npe)),
            ])
        }

        fn get_token_req(&self, pin: &[u8]) -> std::vec::Vec<u8> {
            let h = sha256(pin);
            let phe = self.enc(&h[..16]);
            build(&[
                (1, V::U(self.wire)),
                (2, V::U(5)),
                (3, V::Cose(&self.x, &self.y)),
                (6, V::B(&phe)),
            ])
        }

        fn change_pin_req(&self, old: &[u8], new: &[u8]) -> std::vec::Vec<u8> {
            let mut padded = [0u8; 64];
            padded[..new.len()].copy_from_slice(new);
            let npe = self.enc(&padded);
            let oh = sha256(old);
            let phe = self.enc(&oh[..16]);
            let mut macd = npe.clone();
            macd.extend_from_slice(&phe);
            let puap = self.mac(&macd);
            build(&[
                (1, V::U(self.wire)),
                (2, V::U(4)),
                (3, V::Cose(&self.x, &self.y)),
                (4, V::B(&puap)),
                (5, V::B(&npe)),
                (6, V::B(&phe)),
            ])
        }

        // Decrypt the pinUvAuthToken from a getPinToken response.
        fn decrypt_token(&self, resp: &[u8]) -> [u8; 32] {
            let mut d = Decoder::new(resp);
            assert_eq!(d.map().unwrap().unwrap(), 1);
            assert_eq!(d.u8().unwrap(), 2);
            let enc = d.bytes().unwrap();
            let mut tok = [0u8; 32];
            let n = pinproto::decrypt(self.proto, self.secret(), enc, &mut tok).unwrap();
            assert_eq!(n, 32);
            tok
        }
    }

    fn set_and_get_token(proto: PinProto, wire: u64) {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);

        // setPIN replies with only the status byte (empty body).
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 0);
        assert!(fs.has_data(EF_PIN));

        // getPinToken returns the encrypted token; it decrypts to paut.token.
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(b"1234"),
            &mut out,
        )
        .unwrap();
        let token = plat.decrypt_token(&out[..n]);
        assert_eq!(token, state.paut.token);
        assert_eq!(state.paut.permissions, PERM_MC | PERM_GA);
    }

    #[test]
    fn set_pin_then_get_token_protocol_two() {
        set_and_get_token(PinProto::Two, 2);
    }

    #[test]
    fn set_pin_then_get_token_protocol_one() {
        set_and_get_token(PinProto::One, 1);
    }

    #[cfg(feature = "fips-profile")]
    #[test]
    fn fips_min_pin_floor_is_six() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        // Four code points sit under the profile's floor…
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(b"1234"),
                &mut out
            ),
            Err(CtapError::PinPolicyViolation)
        );
        // …six pass.
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"123456"),
            &mut out,
        )
        .unwrap();
        assert!(fs.has_data(EF_PIN));
    }

    #[test]
    fn forced_pin_change_blocks_tokens_until_change_pin() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();

        // setMinPINLength(forceChangePin) state: [min, force, rpIdHash…].
        let mut mp = [0u8; 2 + 32];
        mp[0] = 4;
        mp[1] = 1;
        mp[2..].copy_from_slice(&sha256(b"example.com"));
        fs.put(EF_MINPINLEN, &mp).unwrap();

        // The *correct* PIN is refused while the flag is up — and the refusal
        // is a policy error, not a failed verify: retries stay full.
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_token_req(b"1234"),
                &mut out
            ),
            Err(CtapError::PinPolicyViolation)
        );
        let mut pf = [0u8; PIN_FILE_LEN];
        assert_eq!(fs.read(EF_PIN, &mut pf), Some(PIN_FILE_LEN));
        assert_eq!(pf[0], MAX_PIN_RETRIES);

        // changePIN satisfies the policy: flag drops, min + RP list survive.
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.change_pin_req(b"1234", b"123456"),
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 0);
        let mut after = [0u8; 2 + 32];
        assert_eq!(fs.read(EF_MINPINLEN, &mut after), Some(2 + 32));
        assert_eq!(after[..2], [4, 0]);
        assert_eq!(after[2..], mp[2..]);

        // Tokens flow again with the new PIN.
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(b"123456"),
            &mut out,
        )
        .unwrap();
    }

    #[test]
    fn seed_stays_loadable_after_pin_ops_and_legacy_wrap_migrates() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);

        // Before a PIN, the seed loads.
        let seed0 = load_keydev(&dev(), &mut fs).unwrap();

        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();
        // Setting a PIN leaves the seed loadable with no session, so a
        // power-cycled UP-only assertion keeps working.
        assert_eq!(load_keydev(&dev(), &mut fs), Some(seed0));

        // A legacy PIN-wrapped blob is unreadable (the UP-only failure window)…
        let pin_hash = sha256(b"1234");
        crate::seed::wrap_keydev_legacy(&dev(), &mut fs, &pin_hash[..16]);
        assert_eq!(load_keydev(&dev(), &mut fs), None);

        // …until the first successful PIN op of any boot migrates it back.
        let mut state2 = FidoState::new();
        let plat2 = key_agreement(&mut fs, &mut rng, &mut state2, PinProto::Two, 2);
        let n = run(
            &mut fs,
            &mut rng,
            &mut state2,
            &plat2.get_token_req(b"1234"),
            &mut out,
        )
        .unwrap();
        let _ = plat2.decrypt_token(&out[..n]);
        assert_eq!(load_keydev(&dev(), &mut fs), Some(seed0));
    }

    #[test]
    fn wrong_pin_decrements_then_locks_out() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();

        // First two wrong attempts: PinInvalid, retry counter drops.
        for _ in 0..2 {
            assert_eq!(
                run(
                    &mut fs,
                    &mut rng,
                    &mut state,
                    &plat.get_token_req(b"9999"),
                    &mut out
                ),
                Err(CtapError::PinInvalid)
            );
        }
        // Third consecutive mismatch trips the per-boot lockout.
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_token_req(b"9999"),
                &mut out
            ),
            Err(CtapError::PinAuthBlocked)
        );
        assert!(state.needs_power_cycle);

        // getPINRetries reflects the three decrements (8 -> 5) and powerCycleState.
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &build(&[(1, V::U(2)), (2, V::U(1))]),
            &mut out,
        )
        .unwrap();
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.u8().unwrap(), MAX_PIN_RETRIES - 3);
    }

    #[test]
    fn change_pin_then_new_pin_works_and_old_fails() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();

        // changePIN replies with only the status byte.
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.change_pin_req(b"1234", b"5678"),
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 0);

        // The new PIN yields a token; the old PIN is now invalid.
        assert!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_token_req(b"5678"),
                &mut out
            )
            .is_ok()
        );
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_token_req(b"1234"),
                &mut out
            ),
            Err(CtapError::PinInvalid)
        );
    }

    #[test]
    fn set_pin_rejects_short_pin_and_double_set() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        // 3-char PIN < minimum 4.
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(b"123"),
                &mut out
            ),
            Err(CtapError::PinPolicyViolation)
        );
        // A valid set, then a second set is NotAllowed.
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(b"4321"),
                &mut out
            ),
            Err(CtapError::NotAllowed)
        );
    }

    #[test]
    fn bad_pin_auth_param_rejected() {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        // A setPIN with a wrong (all-zero) pinUvAuthParam fails authentication.
        let mut padded = [0u8; 64];
        padded[..4].copy_from_slice(b"1234");
        let npe = plat.enc(&padded);
        let bad_mac = [0u8; 32];
        let req = build(&[
            (1, V::U(2)),
            (2, V::U(3)),
            (3, V::Cose(&plat.x, &plat.y)),
            (4, V::B(&bad_mac[..plat.proto.mac_len()])),
            (5, V::B(&npe)),
        ]);
        assert_eq!(
            run(&mut fs, &mut rng, &mut state, &req, &mut out),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn pin_verifier_and_pinwrapped_seed_migrate_at_verify() {
        const OTP_KEY: [u8; 32] = [0x77; 32];
        fn otp_dev() -> Device<'static> {
            Device {
                otp_key: Some(&OTP_KEY),
                ..dev()
            }
        }

        // Legacy pre-OTP state: seed exists, a PIN is set, and the seed was
        // left PIN-wrapped (0x03).
        let (mut fs, mut rng) = setup();
        let seed0 = load_keydev(&dev(), &mut fs).unwrap();
        let mut padded = [0u8; PADDED_PIN_LEN];
        padded[..4].copy_from_slice(b"9246");
        let mut state = FidoState::new();
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            store_new_pin(&mut ctx, &padded).unwrap();
        }
        let pin_hash = sha256(b"9246");
        crate::seed::wrap_keydev_legacy(&dev(), &mut fs, &pin_hash[..16]);
        let mut raw = [0u8; 61];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
        assert_eq!(raw[0], 0x03);

        // The OTP build: first verify migrates the verifier and unwraps the
        // seed straight to a plain 0x11, costing no retry.
        let mut state2 = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state2,
            now_ms: 0,
        };
        verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
        let mut pin_rec = [0u8; PIN_FILE_LEN];
        ctx.fs.read(EF_PIN, &mut pin_rec).unwrap();
        assert_eq!(pin_rec[0], MAX_PIN_RETRIES);
        assert_eq!(ctx.fs.read(EF_KEY_DEV.get(), &mut raw), Some(33));
        assert_eq!(raw[0], 0x11);
        assert_eq!(load_keydev(&otp_dev(), ctx.fs), Some(seed0));

        // Second verify takes the direct path (verifier already re-stored).
        let mut state3 = FidoState::new();
        let mut presence3 = crate::AlwaysConfirm;
        let mut ctx3 = Ctx {
            presence: &mut presence3,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state3,
            now_ms: 0,
        };
        verify_pin_hash(&mut ctx3, &pin_hash[..16]).unwrap();
    }

    #[test]
    fn pin_verify_fails_closed_when_the_retry_write_does_not_persist() {
        use std::cell::Cell;
        use std::rc::Rc;

        // A backend that, once armed, accepts the EF_PIN write (returns Ok) but
        // silently fails to persist it — modelling a glitch / partial flash
        // program. The decremented retry counter never reaches storage, so a later
        // read sees the stale (higher) count: exactly what verify_pin_hash's
        // read-back must catch before trusting the count.
        struct StaleEfPin {
            inner: RamStorage,
            drop_ef_pin_writes: Rc<Cell<bool>>,
        }
        impl Storage for StaleEfPin {
            fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
                self.inner.read(fid, buf)
            }
            fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
                if fid == EF_PIN && self.drop_ef_pin_writes.get() {
                    return Ok(()); // reports success, persists nothing
                }
                self.inner.write(fid, data)
            }
            fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
                self.inner.remove(fid)
            }
            fn size(&mut self, fid: u16) -> Option<usize> {
                self.inner.size(fid)
            }
            fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) {
                self.inner.for_each_key(f)
            }
        }

        let drop_writes = Rc::new(Cell::new(false));
        let mut fs = Fs::new(
            StaleEfPin {
                inner: RamStorage::new(),
                drop_ef_pin_writes: drop_writes.clone(),
            },
            &[],
        );
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

        // Enroll PIN "1234" with writes persisting normally.
        let mut padded = [0u8; PADDED_PIN_LEN];
        padded[..4].copy_from_slice(b"1234");
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut FidoState::new(),
                now_ms: 0,
            };
            store_new_pin(&mut ctx, &padded).unwrap();
        }

        let pin_hash = sha256(b"1234");

        // Control: with the backend healthy, the correct PIN verifies (and resets
        // the counter to full) — so a PinBlocked below can only be the read-back.
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut FidoState::new(),
                now_ms: 0,
            };
            verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
        }

        // Arm the fault: the decremented counter no longer reaches storage. Even
        // with the CORRECT PIN, the read-back sees the stale count and must fail
        // closed rather than proceed on an unverified (un-decremented) counter.
        drop_writes.set(true);
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut FidoState::new(),
            now_ms: 0,
        };
        assert_eq!(
            verify_pin_hash(&mut ctx, &pin_hash[..16]),
            Err(CtapError::PinBlocked),
        );
    }
}
