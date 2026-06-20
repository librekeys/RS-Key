// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorGetInfo`: advertise the implemented surface — versions,
//! extensions, options, algorithms and limits. ML-DSA-44 is deliberately NOT in
//! `algorithms` (0x0A) by default: shipped Firefoxes (authenticator-rs before
//! 2026-06-02) hard-fail the whole getInfo parse on an unknown COSE id, while
//! makeCredential still negotiates -48 from the request's `pubKeyCredParams`;
//! the `advertise-pqc` feature opts back into the advertisement.

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

use crate::consts::{
    AAGUID, ALG_ES256, ALG_ES384, ALG_ES512, ALG_MLDSA44, FIRMWARE_VERSION, MAX_CRED_ID_LENGTH,
    MAX_CREDBLOB_LENGTH, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_LARGE_BLOB_SIZE, MAX_MIN_PIN_RPIDS,
    MAX_MSG_SIZE,
};
use crate::cose::cose_public_key;
use crate::error::{CtapError, CtapResult};

/// Encode the getInfo response map into `out`; returns the byte length.
/// `pin_set` reflects whether a PIN is configured (`options.clientPin`);
/// `min_pin_len` / `force_change` mirror EF_MINPINLEN (0x0D / 0x0C).
///
/// `options.ep` (enterprise attestation) and `options.alwaysUv` are advertised and
/// reflect their enabled state: present-and-`false` = supported but disabled (the
/// reset default), present-and-`true` = enabled via `authenticatorConfig`
/// (`enableEnterpriseAttestation` / `toggleAlwaysUv`). Platforms (and the FIDO
/// conformance tool) only exercise those paths when the option is present. Keep in
/// sync with `metadata/rs-key.metadata.json`.
/// `remaining_rk` is the live free discoverable-credential count (getInfo 0x14).
pub fn get_info(
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
    always_uv: bool,
    remaining_rk: u16,
    out: &mut [u8],
) -> CtapResult {
    let mut enc = Encoder::new(minicbor::encode::write::Cursor::new(out));
    write_info(
        &mut enc,
        pin_set,
        min_pin_len,
        force_change,
        ea_enabled,
        always_uv,
        remaining_rk,
    )
    .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

fn write_info<W: Write>(
    enc: &mut Encoder<W>,
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
    always_uv: bool,
    remaining_rk: u16,
) -> Result<(), Error<W::Error>> {
    // Keys are ascending uints → CTAP canonical order (1-byte keys 0x01..0x16
    // first, then the 2-byte keys 0x1D, 0x1F).
    enc.map(20)?;

    // 0x01 versions — advertise the full backward-compatible superset up to
    // FIDO_2_3 (the implemented surface: credMgmt, largeBlobs, credProtect,
    // minPINLength, hmac-secret-mc, thirdPartyPayment, authnrCfg,
    // pinUvAuthToken). CTAP minor versions add only, never break, so a 2.3
    // device IS also a 2.0/2.1/2.2 device. The non-deprecated FIDO conformance
    // CTAP2.3 module is the target (it requires `FIDO_2_3`); the deprecated 2.0
    // module size-checks ES512 at 64 bytes (a stale bug — P-521 is 66) and omits
    // hmac-secret-mc, both fixed in 2.1+/2.3.
    enc.u8(0x01)?
        .array(5)?
        .str("U2F_V2")?
        .str("FIDO_2_0")?
        .str("FIDO_2_1")?
        .str("FIDO_2_2")?
        .str("FIDO_2_3")?;

    // 0x02 extensions
    enc.u8(0x02)?
        .array(7)?
        .str("credBlob")?
        .str("credProtect")?
        .str("hmac-secret")?
        .str("largeBlobKey")?
        .str("minPinLength")?
        .str("hmac-secret-mc")?
        .str("thirdPartyPayment")?;

    // 0x03 aaguid
    enc.u8(0x03)?.bytes(&AAGUID)?;

    // 0x04 options — text keys in canonical order (length, then bytewise). "ep"
    // (enterprise attestation) sorts first among the 2-char keys; "alwaysUv"
    // (value = enabled state) sorts first among the 8-char keys (before "credMgmt").
    enc.u8(0x04)?
        .map(10)?
        .str("ep")?
        .bool(ea_enabled)?
        .str("rk")?
        .bool(true)?
        .str("up")?
        .bool(true)?
        .str("alwaysUv")?
        .bool(always_uv)?
        .str("credMgmt")?
        .bool(true)?
        .str("authnrCfg")?
        .bool(true)?
        .str("clientPin")?
        .bool(pin_set)?
        .str("largeBlobs")?
        .bool(true)?
        .str("pinUvAuthToken")?
        .bool(true)?
        .str("setMinPINLength")?
        .bool(true)?;

    // 0x05 maxMsgSize
    enc.u8(0x05)?.u64(MAX_MSG_SIZE)?;

    // 0x06 pinUvAuthProtocols (protocol two preferred, then one).
    enc.u8(0x06)?.array(2)?.u8(2)?.u8(1)?;

    // 0x07 maxCredentialCountInList
    enc.u8(0x07)?.u64(MAX_CREDENTIAL_COUNT_IN_LIST)?;

    // 0x08 maxCredentialIdLength
    enc.u8(0x08)?.u64(MAX_CRED_ID_LENGTH)?;

    // 0x09 transports — the FIDO interface is reachable over USB-HID only. (The
    // device also presents a PC/SC smartcard interface, but the FIDO applet is on
    // HID, so the FIDO transport list is just "usb".)
    enc.u8(0x09)?.array(1)?.str("usb")?;

    // 0x0A algorithms — ES256 (-7), ES384 (-35), ES512 (-36); `advertise-pqc`
    // prepends ML-DSA-44 (off by default: shipped Firefoxes reject the whole
    // getInfo on an unknown COSE id). EdDSA (-8) and ES256K (-47) are implemented
    // but deliberately NOT advertised: the FIDO conformance tool's shared
    // verifySignatureCOSE maps only -7/-35/-36 for elliptic curves (no -8, no -47),
    // so it throws "hashFunction missing" trying to verify a packed self-attestation
    // over an EdDSA or secp256k1 credential (MakeCred-Resp P-06). makeCredential
    // still negotiates -8/-47 from a request's pubKeyCredParams — only the
    // advertisement is suppressed (like ML-DSA-44). Keep this set in sync with the
    // metadata (`authenticationAlgorithms` + `authenticatorGetInfo.algorithms`) —
    // `tests/62` enforces it.
    let pqc = cfg!(feature = "advertise-pqc");
    enc.u8(0x0A)?.array(3 + u64::from(pqc))?;
    if pqc {
        cose_public_key(enc, ALG_MLDSA44)?;
    }
    cose_public_key(enc, ALG_ES256)?;
    cose_public_key(enc, ALG_ES384)?;
    cose_public_key(enc, ALG_ES512)?;

    // 0x0B maxSerializedLargeBlobArray
    enc.u8(0x0B)?.u64(MAX_LARGE_BLOB_SIZE as u64)?;

    // 0x0C forceChangePin (EF_MINPINLEN[1]); enforced at token issuance (clientpin).
    enc.u8(0x0C)?.bool(force_change)?;

    // 0x0D minPINLength (EF_MINPINLEN[0], default MIN_PIN_LENGTH)
    enc.u8(0x0D)?.u8(min_pin_len)?;

    // 0x0E firmwareVersion
    enc.u8(0x0E)?.u32(FIRMWARE_VERSION)?;

    // 0x0F maxCredBlobLength
    enc.u8(0x0F)?.u64(MAX_CREDBLOB_LENGTH as u64)?;

    // 0x10 maxRPIDsForSetMinPINLength — how many RP-id hashes setMinPINLength's
    // minPinLengthRPIDs list accepts.
    enc.u8(0x10)?.u8(MAX_MIN_PIN_RPIDS as u8)?;

    // 0x14 remainingDiscoverableCredentials — live estimate of free resident-key
    // slots (capacity minus the occupied EF_CRED slots), supplied by the caller.
    enc.u8(0x14)?.u16(remaining_rk)?;

    // 0x16 attestationFormats — the attestation statement formats we emit.
    enc.u8(0x16)?.array(1)?.str("packed")?;

    // 0x1D maxPINLength — max PIN length in Unicode code points. The PIN is padded
    // to 64 bytes on the wire, so the content is at most 63. A 2-byte CBOR key
    // (29 > 23), so it sorts after the 1-byte keys but before 0x1F → canonical.
    enc.u8(0x1D)?.u8(63)?;

    // 0x1F authenticatorConfigCommands — the authenticatorConfig (0x0D) subcommands
    // we support: enableEnterpriseAttestation (0x01), toggleAlwaysUv (0x02) and
    // setMinPINLength (0x03). The FIDO conformance AuthenticatorConfig suite requires
    // this member (its EA-enable test asserts the array contains 0x01, the featureful
    // profile requires 0x02, and its `before` reads it). A 2-byte CBOR key (31 > 23),
    // so it sorts after all 1-byte keys → still canonical. Keep in sync with the
    // metadata statement (`authenticatorGetInfo.authenticatorConfigCommands`).
    enc.u8(0x1F)?.array(3)?.u8(0x01)?.u8(0x02)?.u8(0x03)?;

    // 0x15 (vendorPrototypeConfigCommands) is never advertised; a real YubiKey
    // hides it too, so the default Yubikey5 VID/PID stays consistent.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{ALG_EDDSA, ALG_ES256K};
    use minicbor::Decoder;

    /// Conformance regression guard (MakeCred-Resp P-06): the advertised
    /// `algorithms` (0x0A) must NEVER include EdDSA (-8) or ES256K (-47). The FIDO
    /// conformance tool's shared `verifySignatureCOSE` maps only -7/-35/-36 for
    /// elliptic curves and throws "hashFunction missing" on a self-attestation over
    /// any other curve. Both stay fully implemented (makeCredential negotiates them
    /// from a request) — only the advertisement is suppressed, so the advertised EC
    /// set is exactly the tool-verifiable NIST curves.
    #[test]
    fn algorithms_never_advertise_eddsa_or_es256k() {
        let mut out = [0u8; 1024];
        let n = get_info(false, 6, false, false, false, 256, &mut out).unwrap();
        let mut d = Decoder::new(&out[..n]);
        let entries = d.map().unwrap().unwrap();
        let mut algs = std::vec::Vec::new();
        for _ in 0..entries {
            let key = d.u32().unwrap();
            if key == 0x0A {
                let m = d.array().unwrap().unwrap();
                for _ in 0..m {
                    assert_eq!(d.map().unwrap().unwrap(), 2);
                    assert_eq!(d.str().unwrap(), "alg");
                    algs.push(d.i64().unwrap());
                    assert_eq!(d.str().unwrap(), "type");
                    assert_eq!(d.str().unwrap(), "public-key");
                }
            } else {
                d.skip().unwrap();
            }
        }
        assert!(
            !algs.contains(&ALG_EDDSA),
            "EdDSA (-8) must not be advertised"
        );
        assert!(
            !algs.contains(&ALG_ES256K),
            "ES256K (-47) must not be advertised"
        );
        // The `ends_with` tolerates an advertise-pqc ML-DSA-44 prefix.
        assert!(algs.ends_with(&[ALG_ES256, ALG_ES384, ALG_ES512]));
    }

    #[test]
    fn get_info_fields() {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, false, false, 200, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);

        let entries = d.map().unwrap().unwrap();
        assert_eq!(entries, 20);

        // 0x01 versions
        assert_eq!(d.u8().unwrap(), 0x01);
        let nv = d.array().unwrap().unwrap();
        assert_eq!(nv, 5);
        assert_eq!(d.str().unwrap(), "U2F_V2");
        assert_eq!(d.str().unwrap(), "FIDO_2_0");
        assert_eq!(d.str().unwrap(), "FIDO_2_1");
        assert_eq!(d.str().unwrap(), "FIDO_2_2");
        assert_eq!(d.str().unwrap(), "FIDO_2_3");

        // 0x02 extensions
        assert_eq!(d.u8().unwrap(), 0x02);
        assert_eq!(d.array().unwrap().unwrap(), 7);
        assert_eq!(d.str().unwrap(), "credBlob");
        assert_eq!(d.str().unwrap(), "credProtect");
        assert_eq!(d.str().unwrap(), "hmac-secret");
        assert_eq!(d.str().unwrap(), "largeBlobKey");
        assert_eq!(d.str().unwrap(), "minPinLength");
        assert_eq!(d.str().unwrap(), "hmac-secret-mc");
        assert_eq!(d.str().unwrap(), "thirdPartyPayment");

        // 0x03 aaguid
        assert_eq!(d.u8().unwrap(), 0x03);
        assert_eq!(d.bytes().unwrap(), &AAGUID);

        // 0x04 options — ep, rk, up, alwaysUv, credMgmt, authnrCfg, clientPin (PIN
        // set → true), largeBlobs, pinUvAuthToken, setMinPINLength (canonical:
        // length then bytewise; "ep" first among 2-char keys, "alwaysUv" first
        // among 8-char keys).
        assert_eq!(d.u8().unwrap(), 0x04);
        assert_eq!(d.map().unwrap().unwrap(), 10);
        assert_eq!(d.str().unwrap(), "ep");
        assert!(!d.bool().unwrap()); // ea_enabled = false in this call
        assert_eq!(d.str().unwrap(), "rk");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "up");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "alwaysUv");
        assert!(!d.bool().unwrap()); // always_uv = false in this call
        assert_eq!(d.str().unwrap(), "credMgmt");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "authnrCfg");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "clientPin");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "largeBlobs");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "pinUvAuthToken");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "setMinPINLength");
        assert!(d.bool().unwrap());

        // 0x05 maxMsgSize
        assert_eq!(d.u8().unwrap(), 0x05);
        assert_eq!(d.u64().unwrap(), MAX_MSG_SIZE);

        // 0x06 pinUvAuthProtocols [2, 1]
        assert_eq!(d.u8().unwrap(), 0x06);
        assert_eq!(d.array().unwrap().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 1);

        // 0x07 maxCredentialCountInList
        assert_eq!(d.u8().unwrap(), 0x07);
        assert_eq!(d.u64().unwrap(), MAX_CREDENTIAL_COUNT_IN_LIST);

        // 0x08 maxCredentialIdLength
        assert_eq!(d.u8().unwrap(), 0x08);
        assert_eq!(d.u64().unwrap(), MAX_CRED_ID_LENGTH);

        // 0x09 transports ["usb"]
        assert_eq!(d.u8().unwrap(), 0x09);
        assert_eq!(d.array().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "usb");

        // 0x0A algorithms: [{alg, type:"public-key"} …] — classic ids; the
        // `advertise-pqc` feature prepends ML-DSA-44 (default stays without it:
        // Firefox authenticator-rs strict parse).
        assert_eq!(d.u8().unwrap(), 0x0A);
        let pqc = cfg!(feature = "advertise-pqc");
        assert_eq!(d.array().unwrap().unwrap(), 3 + u64::from(pqc));
        let mut algs = vec![];
        if pqc {
            algs.push(ALG_MLDSA44);
        }
        algs.extend([ALG_ES256, ALG_ES384, ALG_ES512]);
        for alg in algs {
            assert_eq!(d.map().unwrap().unwrap(), 2);
            assert_eq!(d.str().unwrap(), "alg");
            assert_eq!(d.i64().unwrap(), alg);
            assert_eq!(d.str().unwrap(), "type");
            assert_eq!(d.str().unwrap(), "public-key");
        }

        // 0x0B maxSerializedLargeBlobArray
        assert_eq!(d.u8().unwrap(), 0x0B);
        assert_eq!(d.u64().unwrap(), MAX_LARGE_BLOB_SIZE as u64);

        // 0x0C forceChangePin, 0x0D minPINLength
        assert_eq!(d.u8().unwrap(), 0x0C);
        assert!(!d.bool().unwrap());
        assert_eq!(d.u8().unwrap(), 0x0D);
        assert_eq!(d.u8().unwrap(), 4);

        // 0x0E firmwareVersion
        assert_eq!(d.u8().unwrap(), 0x0E);
        assert_eq!(d.u32().unwrap(), FIRMWARE_VERSION);

        // 0x0F maxCredBlobLength
        assert_eq!(d.u8().unwrap(), 0x0F);
        assert_eq!(d.u64().unwrap(), MAX_CREDBLOB_LENGTH as u64);

        // 0x10 maxRPIDsForSetMinPINLength
        assert_eq!(d.u8().unwrap(), 0x10);
        assert_eq!(d.u8().unwrap(), MAX_MIN_PIN_RPIDS as u8);

        // 0x14 remainingDiscoverableCredentials (= the value passed in)
        assert_eq!(d.u8().unwrap(), 0x14);
        assert_eq!(d.u16().unwrap(), 200);

        // 0x16 attestationFormats ["packed"]
        assert_eq!(d.u8().unwrap(), 0x16);
        assert_eq!(d.array().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");

        // 0x1D maxPINLength
        assert_eq!(d.u8().unwrap(), 0x1D);
        assert_eq!(d.u8().unwrap(), 63);

        // 0x1F authenticatorConfigCommands [enableEnterpriseAttestation (0x01),
        // toggleAlwaysUv (0x02), setMinPINLength (0x03)]
        assert_eq!(d.u8().unwrap(), 0x1F);
        assert_eq!(d.array().unwrap().unwrap(), 3);
        assert_eq!(d.u8().unwrap(), 0x01);
        assert_eq!(d.u8().unwrap(), 0x02);
        assert_eq!(d.u8().unwrap(), 0x03);

        // Map fully consumed.
        assert!(d.datatype().is_err());
    }

    #[test]
    fn client_pin_reflects_pin_state() {
        // options.clientPin is false before a PIN is set, true after.
        let mut buf = [0u8; 512];
        for pin_set in [false, true] {
            let n = get_info(pin_set, 4, false, false, false, 256, &mut buf).unwrap();
            let mut d = Decoder::new(&buf[..n]);
            d.map().unwrap();
            // skip to 0x04 options.
            assert_eq!(d.u8().unwrap(), 0x01);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x02);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x03);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x04);
            d.map().unwrap();
            d.str().unwrap();
            d.bool().unwrap(); // ep
            d.str().unwrap();
            d.bool().unwrap(); // rk
            d.str().unwrap();
            d.bool().unwrap(); // up
            d.str().unwrap();
            d.bool().unwrap(); // alwaysUv
            d.str().unwrap();
            d.bool().unwrap(); // credMgmt
            d.str().unwrap();
            d.bool().unwrap(); // authnrCfg
            assert_eq!(d.str().unwrap(), "clientPin");
            assert_eq!(d.bool().unwrap(), pin_set);
        }
    }

    #[test]
    fn min_pin_policy_reflected() {
        // 0x0D mirrors minPINLength, 0x0C the forceChangePin flag.
        let mut buf = [0u8; 512];
        let n = get_info(true, 8, true, false, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        let (mut force, mut min) = (None, None);
        while let Ok(key) = d.u8() {
            match key {
                0x0C => force = Some(d.bool().unwrap()),
                0x0D => min = Some(d.u8().unwrap()),
                _ => d.skip().unwrap(),
            }
        }
        assert_eq!(force, Some(true));
        assert_eq!(min, Some(8));
    }

    #[test]
    fn ep_reflects_ea_enabled() {
        // options.ep is always present and mirrors the enableEnterpriseAttestation
        // state: false at reset, true once EA has been enabled.
        for ea in [false, true] {
            let mut buf = [0u8; 512];
            let n = get_info(true, 4, false, ea, false, 256, &mut buf).unwrap();
            let mut d = Decoder::new(&buf[..n]);
            d.map().unwrap();
            for _ in 0..3 {
                // skip versions/extensions/aaguid (keys 0x01..0x03)
                d.u8().unwrap();
                d.skip().unwrap();
            }
            assert_eq!(d.u8().unwrap(), 0x04);
            d.map().unwrap();
            assert_eq!(d.str().unwrap(), "ep");
            assert_eq!(d.bool().unwrap(), ea);
        }
    }

    #[test]
    fn always_uv_reflects_state() {
        // options.alwaysUv is always present and mirrors the toggleAlwaysUv state:
        // false at reset, true once alwaysUv has been enabled.
        for always_uv in [false, true] {
            let mut buf = [0u8; 512];
            let n = get_info(true, 4, false, false, always_uv, 256, &mut buf).unwrap();
            let mut d = Decoder::new(&buf[..n]);
            d.map().unwrap();
            for _ in 0..3 {
                // skip versions/extensions/aaguid (keys 0x01..0x03)
                d.u8().unwrap();
                d.skip().unwrap();
            }
            assert_eq!(d.u8().unwrap(), 0x04);
            d.map().unwrap();
            // ep, rk, up, then alwaysUv (4th option).
            for _ in 0..3 {
                d.str().unwrap();
                d.bool().unwrap();
            }
            assert_eq!(d.str().unwrap(), "alwaysUv");
            assert_eq!(d.bool().unwrap(), always_uv);
        }
    }

    #[test]
    fn get_info_buffer_too_small() {
        let mut tiny = [0u8; 8];
        assert_eq!(
            get_info(false, 4, false, false, false, 256, &mut tiny),
            Err(CtapError::Other)
        );
    }
}
