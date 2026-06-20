// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorConfig`: enableEnterpriseAttestation (0x01), toggleAlwaysUv
//! (0x02), setMinPINLength (0x03) and the vendor arm (0xFF) carrying the soft-lock
//! pair AUT_ENABLE / AUT_DISABLE — all gated on a `pinUvAuthParam` with the `acfg`
//! permission; the soft-lock pair additionally requires a physical touch.

use minicbor::Decoder;
use rsk_fs::{Sealed, Storage};
use zeroize::Zeroize;

use rsk_crypto::pinproto::PinProto;
use rsk_crypto::sha256;

use crate::cbordec::{cbor, def_arr, def_map};
use crate::consts::{
    CONFIG_AUT_DISABLE, CONFIG_AUT_ENABLE, CONFIG_ENABLE_EA, CONFIG_SET_MIN_PIN,
    CONFIG_TOGGLE_ALWAYS_UV, CONFIG_VENDOR, CTAP_CONFIG, EF_ALWAYS_UV, EF_EA_ENABLED, EF_KEY_DEV,
    EF_KEY_DEV_ENC, EF_MINPINLEN, EF_PIN, MAX_MIN_PIN_RPIDS, MIN_PIN_LENGTH,
};
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::{encrypt_keydev_f1, load_keydev, lock_engaged, seal_seed_locked};
use crate::state::PERM_ACFG;
use crate::vendor::open_channel_key;
use crate::{Ctx, Rng};

const MAX_RAW_SUBPARA: usize = 256;

struct Req<'a> {
    subcommand: u64,
    raw_subpara: &'a [u8],
    proto: u64,
    pin_uv_auth_param: Option<&'a [u8]>,
    new_min_pin: u64,
    force_change: bool,
    rp_ids: [&'a str; MAX_MIN_PIN_RPIDS],
    rp_ids_len: usize,
    /// Vendor (0xFF) subCommandParams: `{1: vendorCommandId, 2: byte param}`.
    vendor_id: u64,
    vendor_param: &'a [u8],
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        subcommand: 0,
        raw_subpara: &[],
        proto: 0,
        pin_uv_auth_param: None,
        new_min_pin: 0,
        force_change: false,
        rp_ids: [""; MAX_MIN_PIN_RPIDS],
        rp_ids_len: 0,
        vendor_id: 0,
        vendor_param: &[],
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Key 1 (subCommand) is mandatory and first.
        if expected <= 1 && key != 1 {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => {
                // Capture the raw subCommandParams bytes (covered by the MAC) while
                // extracting the fields setMinPINLength needs.
                let start = d.position();
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    let sk = cbor(d.u32())? as u64;
                    if req.subcommand == CONFIG_SET_MIN_PIN {
                        match sk {
                            1 => req.new_min_pin = cbor(d.u32())? as u64,
                            2 => {
                                let a = def_arr(&mut d)?;
                                for _ in 0..a {
                                    let id = cbor(d.str())?;
                                    if req.rp_ids_len < MAX_MIN_PIN_RPIDS {
                                        req.rp_ids[req.rp_ids_len] = id;
                                        req.rp_ids_len += 1;
                                    }
                                }
                            }
                            3 => req.force_change = cbor(d.bool())?,
                            _ => cbor(d.skip())?,
                        }
                    } else if req.subcommand == CONFIG_VENDOR {
                        match sk {
                            1 => req.vendor_id = cbor(d.u64())?,
                            2 => req.vendor_param = cbor(d.bytes())?,
                            _ => cbor(d.skip())?,
                        }
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

/// `authenticatorConfig`: verify the pinUvAuthParam, then run the subcommand.
/// Replies with only the status byte.
pub fn authenticator_config<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let _ = out;
    let req = parse(data)?;

    let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
    if req.proto == 0 {
        return Err(CtapError::MissingParameter);
    }
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;
    if req.raw_subpara.len() > MAX_RAW_SUBPARA {
        return Err(CtapError::RequestTooLarge);
    }

    // verify_payload = 0xff×32 ‖ 0x0d ‖ subcommand ‖ raw subCommandParams.
    let mut vp = [0u8; 32 + 2 + MAX_RAW_SUBPARA];
    vp[..32].fill(0xff);
    vp[32] = CTAP_CONFIG;
    vp[33] = req.subcommand as u8;
    vp[34..34 + req.raw_subpara.len()].copy_from_slice(req.raw_subpara);
    let vp_len = 34 + req.raw_subpara.len();

    if !ctx.state.verify_token(proto, &vp[..vp_len], param)
        || ctx.state.paut.permissions & PERM_ACFG == 0
    {
        return Err(CtapError::PinAuthInvalid);
    }

    match req.subcommand {
        CONFIG_ENABLE_EA => {
            // Persists until authenticatorReset (CTAP 2.1) — flash, not RAM.
            ctx.fs
                .put(EF_EA_ENABLED, &[1])
                .map_err(|_| CtapError::Other)?;
            journal::append(ctx, journal::EV_CFG_EA, 0, &[]);
            Ok(0)
        }
        CONFIG_TOGGLE_ALWAYS_UV => toggle_always_uv(ctx),
        CONFIG_SET_MIN_PIN => set_min_pin_length(
            ctx,
            req.new_min_pin,
            req.force_change,
            &req.rp_ids[..req.rp_ids_len],
        ),
        CONFIG_VENDOR => match req.vendor_id {
            CONFIG_AUT_ENABLE => aut_enable(ctx, req.vendor_param),
            CONFIG_AUT_DISABLE => aut_disable(ctx),
            _ => Err(CtapError::InvalidSubcommand),
        },
        _ => Err(CtapError::UnsupportedOption),
    }
}

/// `toggleAlwaysUv` (CTAP 2.1 §6.11): flip the alwaysUv state. While enabled,
/// every makeCredential / getAssertion requires user verification (a verified
/// pinUvAuthToken), not merely user presence — enforced in those commands'
/// `enforce_pin`. Disabling is supported, so the conformance toggle test
/// (AuthenticatorConfig P-2) observes the opposite value. State is the presence of
/// `EF_ALWAYS_UV`; it persists until authenticatorReset (flash, CTAP 2.1).
fn toggle_always_uv<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if ctx.fs.has_data(EF_ALWAYS_UV) {
        ctx.fs.delete(EF_ALWAYS_UV).map_err(|_| CtapError::Other)?;
    } else {
        ctx.fs
            .put(EF_ALWAYS_UV, &[1])
            .map_err(|_| CtapError::Other)?;
    }
    journal::append(ctx, journal::EV_CFG_ALWAYS_UV, 0, &[]);
    Ok(0)
}

/// `AUT_ENABLE`: engage the soft lock. The host sends a 32-byte lock key over
/// the MSE channel; the seed value is AEAD-wrapped under it into
/// `EF_KEY_DEV_ENC` and the plain `EF_KEY_DEV` is deleted. From here every
/// power cycle needs a vendor UNLOCK before any FIDO operation; recovery from a
/// lost lock key is an authenticatorReset (the identity is gone — by design).
fn aut_enable<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, param: &[u8]) -> CtapResult {
    if !ctx.fs.has_key(EF_KEY_DEV) {
        return Err(CtapError::NotAllowed); // already locked, or no seed at all
    }
    if !ctx.state.mse_active {
        return Err(CtapError::NotAllowed);
    }
    let mut lock_key = open_channel_key(ctx, param)?;
    if !ctx.check_user_presence() {
        lock_key.zeroize();
        return Err(CtapError::OperationDenied);
    }
    let seed = load_keydev(&ctx.dev, ctx.fs);
    let r = seed.map(|mut seed| {
        let blob = seal_seed_locked(ctx.rng, &lock_key, &seed);
        seed.zeroize();
        ctx.fs
            .put_key(EF_KEY_DEV_ENC, Sealed::wrap(&blob))
            .and_then(|()| ctx.fs.delete_key(EF_KEY_DEV))
    });
    lock_key.zeroize();
    match r {
        Some(Ok(())) => {
            journal::append(ctx, journal::EV_LOCK_ENGAGE, 0, &[]);
            Ok(0)
        }
        _ => Err(CtapError::Other),
    }
}

/// `AUT_DISABLE`: release the soft lock. Requires the seed unlocked this power
/// cycle (proof of the lock key); writes it back kbase-sealed and deletes the
/// wrapped blob.
fn aut_disable<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if !lock_engaged(ctx.fs) {
        return Err(CtapError::NotAllowed);
    }
    if ctx.state.keydev_dec.is_none() {
        return Err(CtapError::PinAuthInvalid);
    }
    if !ctx.check_user_presence() {
        return Err(CtapError::OperationDenied);
    }
    let mut seed = ctx.state.keydev_dec.unwrap();
    let r = encrypt_keydev_f1(&ctx.dev, ctx.fs, &seed);
    seed.zeroize();
    r.map_err(|_| CtapError::Other)?;
    ctx.fs
        .delete_key(EF_KEY_DEV_ENC)
        .map_err(|_| CtapError::Other)?;
    ctx.state.clear_keydev_dec();
    journal::append(ctx, journal::EV_LOCK_RELEASE, 0, &[]);
    Ok(0)
}

fn set_min_pin_length<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    new_min_pin: u64,
    force_change: bool,
    rp_ids: &[&str],
) -> CtapResult {
    let current = current_min_pin(ctx) as u64;
    let new_min = if new_min_pin == 0 {
        current
    } else {
        new_min_pin
    };
    // minPINLength is monotonic — it can only grow.
    if new_min < current {
        return Err(CtapError::PinPolicyViolation);
    }
    let pin_set = ctx.fs.has_data(EF_PIN);
    if force_change && !pin_set {
        return Err(CtapError::PinNotSet);
    }
    // A PIN shorter than the new minimum must be changed before next use.
    let mut force = force_change;
    if pin_set {
        let mut pf = [0u8; 35];
        if let Some(n) = ctx.fs.read(EF_PIN, &mut pf)
            && n >= 2
            && (pf[1] as u64) < new_min
        {
            force = true;
        }
    }
    if force {
        ctx.state.reset_pin_uv_auth_token(ctx.rng);
        ctx.state.reset_persistent_token(ctx.rng);
    }
    // EF_MINPINLEN = [minPINLength, forceChangePin, sha256(rpId)…]; the rp hash
    // list authorises those RPs to read minPINLength via the makeCredential
    // extension.
    let mut data = [0u8; 2 + 32 * MAX_MIN_PIN_RPIDS];
    data[0] = new_min as u8;
    data[1] = u8::from(force);
    let mut len = 2;
    for id in rp_ids {
        data[len..len + 32].copy_from_slice(&sha256(id.as_bytes()));
        len += 32;
    }
    ctx.fs
        .put(EF_MINPINLEN, &data[..len])
        .map_err(|_| CtapError::Other)?;
    journal::append(
        ctx,
        journal::EV_CFG_MIN_PIN,
        new_min as u8,
        &[u8::from(force)],
    );
    Ok(0)
}

fn current_min_pin<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> u8 {
    let mut buf = [0u8; 2];
    match ctx.fs.read(EF_MINPINLEN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MIN_PIN_LENGTH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FidoState;
    use minicbor::Encoder;
    use minicbor::encode::write::Cursor;
    use rsk_crypto::Device;
    use rsk_crypto::pinproto;
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

    const TOKEN: [u8; 32] = [0x99; 32];

    fn armed(perms: u8) -> FidoState {
        let mut s = FidoState::new();
        s.paut.token = TOKEN;
        s.paut.permissions = perms;
        s.begin_using_token(false);
        s
    }

    // The setMinPINLength subCommandParams map `{1: new_min}`.
    fn subpara_min_pin(new_min: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 32];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(1).unwrap().u8(1).unwrap().u64(new_min).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // Build a config request, MACing over 0xff×32 ‖ 0x0d ‖ subcmd ‖ subpara.
    fn config_request(subcmd: u8, subpara: &[u8], token: &[u8; 32]) -> std::vec::Vec<u8> {
        let mut vp = std::vec![0xffu8; 32];
        vp.push(CTAP_CONFIG);
        vp.push(subcmd);
        vp.extend_from_slice(subpara);
        let mut mac = [0u8; 32];
        let mlen = pinproto::authenticate(PinProto::Two, token, &vp, &mut mac).unwrap();

        let mut req = std::vec::Vec::new();
        let fields = if subpara.is_empty() { 3u8 } else { 4 };
        req.push(0xA0 | fields); // map(fields)
        req.extend_from_slice(&[0x01, subcmd]); // 1: subCommand
        if !subpara.is_empty() {
            req.push(0x02); // 2: subCommandParams (raw)
            req.extend_from_slice(subpara);
        }
        req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
        req.push(0x04); // 4: pinUvAuthParam
        req.push(0x58); // byte string, 1-byte length
        req.push(mlen as u8);
        req.extend_from_slice(&mac[..mlen]);
        req
    }

    fn run(state: &mut FidoState, req: &[u8]) -> CtapResult {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let mut out = [0u8; 64];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state,
            now_ms: 0,
        };
        authenticator_config(&mut ctx, req, &mut out)
    }

    fn run_fs(fs: &mut Fs<RamStorage>, state: &mut FidoState, req: &[u8]) -> CtapResult {
        let mut rng = SeqRng(1);
        let mut out = [0u8; 64];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng: &mut rng,
            state,
            now_ms: 0,
        };
        authenticator_config(&mut ctx, req, &mut out)
    }

    #[test]
    fn set_min_pin_length_stores_policy() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_ACFG);
        let req = config_request(0x03, &subpara_min_pin(6), &TOKEN);
        assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
        let mut buf = [0u8; 2];
        assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
        assert_eq!(buf, [6, 0]); // minPINLength 6, no forced change
    }

    #[test]
    fn toggle_always_uv_flips_state() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_ACFG);
        let req = config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN);
        // Off by default; first toggle enables, second disables.
        assert!(!fs.has_data(EF_ALWAYS_UV));
        assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
        assert!(fs.has_data(EF_ALWAYS_UV));
        assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
        assert!(!fs.has_data(EF_ALWAYS_UV));
    }

    #[test]
    fn toggle_always_uv_requires_acfg_permission() {
        // The shared token check rejects a token lacking the acfg permission, so
        // alwaysUv cannot be flipped without it.
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(0);
        let req = config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN);
        assert_eq!(
            run_fs(&mut fs, &mut state, &req),
            Err(CtapError::PinAuthInvalid)
        );
        assert!(!fs.has_data(EF_ALWAYS_UV));
    }

    // setMinPINLength subCommandParams `{1: new_min, 2: [rpIds…]}`.
    fn subpara_min_pin_rpids(new_min: u64, rp_ids: &[&str]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 128];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(2).unwrap();
            e.u8(1).unwrap().u64(new_min).unwrap();
            e.u8(2).unwrap().array(rp_ids.len() as u64).unwrap();
            for id in rp_ids {
                e.str(id).unwrap();
            }
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    #[test]
    fn set_min_pin_stores_rpid_hashes() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_ACFG);
        let req = config_request(0x03, &subpara_min_pin_rpids(6, &["example.com"]), &TOKEN);
        assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
        // EF_MINPINLEN = [6, 0, sha256("example.com")].
        let mut buf = [0u8; 2 + 32];
        assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2 + 32));
        assert_eq!(buf[0], 6);
        assert_eq!(&buf[2..], &sha256(b"example.com"));
    }

    #[test]
    fn set_min_pin_cannot_be_lowered() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_ACFG);
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(8), &TOKEN),
        )
        .unwrap();
        // 6 < current 8 → policy violation.
        assert_eq!(
            run_fs(
                &mut fs,
                &mut state,
                &config_request(0x03, &subpara_min_pin(6), &TOKEN)
            ),
            Err(CtapError::PinPolicyViolation)
        );
    }

    #[test]
    fn config_requires_acfg_permission() {
        // A token without the acfg permission is rejected.
        let mut state = armed(crate::state::PERM_MC);
        assert_eq!(
            run(
                &mut state,
                &config_request(0x03, &subpara_min_pin(6), &TOKEN)
            ),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn config_bad_mac_rejected() {
        let mut state = armed(PERM_ACFG);
        // MAC under the wrong token → PinAuthInvalid.
        let req = config_request(0x03, &subpara_min_pin(6), &[0x11; 32]);
        assert_eq!(run(&mut state, &req), Err(CtapError::PinAuthInvalid));
    }

    #[test]
    fn config_without_param_is_puat_required() {
        let mut state = armed(PERM_ACFG);
        // {1: 3} — no pinUvAuthParam.
        let req = std::vec![0xA1, 0x01, 0x03];
        assert_eq!(run(&mut state, &req), Err(CtapError::PuatRequired));
    }

    #[test]
    fn enable_enterprise_attestation() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = armed(PERM_ACFG);
        let req = config_request(0x01, &[], &TOKEN);
        assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
        // Persisted: a fresh power cycle (new FidoState) still sees it.
        assert!(fs.has_data(EF_EA_ENABLED));
    }

    #[test]
    fn set_min_pin_forces_change_when_pin_too_short() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        // A 4-char PIN on file (`[retries, len, format, verifier…]`).
        let mut pin_file = [0u8; 35];
        pin_file[0] = 8;
        pin_file[1] = 4;
        pin_file[2] = 1;
        fs.put(EF_PIN, &pin_file).unwrap();
        let mut state = armed(PERM_ACFG);
        // Raising the minimum above the current PIN length forces a change and
        // resets the token.
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(6), &TOKEN),
        )
        .unwrap();
        let mut buf = [0u8; 2];
        fs.read(EF_MINPINLEN, &mut buf).unwrap();
        assert_eq!(buf, [6, 1]); // forceChangePin set
        assert_ne!(state.paut.token, TOKEN); // token regenerated
    }
}
