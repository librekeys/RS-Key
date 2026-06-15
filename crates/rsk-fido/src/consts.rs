// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! FIDO constants — AIDs, CTAP command bytes, COSE algorithms/curves, auth-data
//! flags, the AAGUID, size limits and flash file ids.

/// FIDO2 applet AID.
pub const FIDO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
/// Backup FIDO2 applet AID.
pub const FIDO_AID_BACKUP: &[u8] = &[0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
/// U2F applet AID.
pub const U2F_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02];

// CTAP1 / U2F command INS bytes.
pub const CTAP_REGISTER: u8 = 0x01;
pub const CTAP_AUTHENTICATE: u8 = 0x02;
pub const CTAP_VERSION: u8 = 0x03;
/// The U2F APDU INS that carries a CTAP2 CBOR message.
pub const CTAP_CBOR: u8 = 0x10;

// CTAP2 command bytes (the first byte of a CTAPHID_CBOR message).
pub const CTAP_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_GET_ASSERTION: u8 = 0x02;
pub const CTAP_GET_INFO: u8 = 0x04;
pub const CTAP_CLIENT_PIN: u8 = 0x06;
pub const CTAP_RESET: u8 = 0x07;
pub const CTAP_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP_CREDENTIAL_MGMT: u8 = 0x0A;
pub const CTAP_SELECTION: u8 = 0x0B;
pub const CTAP_LARGE_BLOBS: u8 = 0x0C;
pub const CTAP_CONFIG: u8 = 0x0D;
pub const CTAP_VENDOR: u8 = 0x41; // vendor range: seed backup + MSE channel

// authenticatorVendor (0x41) subcommands — wallet-style seed backup. Export hands
// the raw 32-byte seed *value* over the encrypted MSE channel so the host can
// render it as a BIP-39 / SLIP-39 mnemonic; restore re-seals it under this
// chip's kbase.
pub const VENDOR_MSE: u64 = 0x01; // establish the ECDH key-agreement channel
pub const VENDOR_BACKUP_EXPORT: u64 = 0x02; // hand the seed to the host (gated)
pub const VENDOR_BACKUP_LOAD: u64 = 0x03; // install a seed from the host (gated)
pub const VENDOR_BACKUP_FINALIZE: u64 = 0x04; // seal the one-time export window
pub const VENDOR_BACKUP_STATE: u64 = 0x05; // read the lock/backup flags (ungated)
pub const VENDOR_UNLOCK: u64 = 0x06; // soft-lock: decrypt EF_KEY_DEV_ENC to RAM
pub const VENDOR_AUDIT_READ: u64 = 0x07; // export the audit journal window
pub const VENDOR_AUDIT_CHECKPOINT: u64 = 0x08; // DEVK-signed chain checkpoint
pub const VENDOR_ATT_IMPORT: u64 = 0x09; // install org attestation key + chain
pub const VENDOR_ATT_CLEAR: u64 = 0x0A; // remove the org attestation
pub const VENDOR_ATT_STATE: u64 = 0x0B; // {present, chain hash} — ungated

// authenticatorConfig subcommands.
pub const CONFIG_ENABLE_EA: u64 = 0x01; // enableEnterpriseAttestation
pub const CONFIG_SET_MIN_PIN: u64 = 0x03; // setMinPINLength
pub const CONFIG_VENDOR: u64 = 0xFF; // vendor subcommands, selected by a u64 id

// authenticatorConfig vendor command ids — the soft-lock enable/disable pair.
pub const CONFIG_AUT_ENABLE: u64 = 0x03e43f56b34285e2;
pub const CONFIG_AUT_DISABLE: u64 = 0x1831a40f04a25ed9;

// authenticatorCredentialManagement subcommands.
pub const CM_GET_CREDS_METADATA: u64 = 0x01;
pub const CM_ENUMERATE_RPS_BEGIN: u64 = 0x02;
pub const CM_ENUMERATE_RPS_NEXT: u64 = 0x03;
pub const CM_ENUMERATE_CREDS_BEGIN: u64 = 0x04;
pub const CM_ENUMERATE_CREDS_NEXT: u64 = 0x05;
pub const CM_DELETE_CREDENTIAL: u64 = 0x06;
pub const CM_UPDATE_USER_INFO: u64 = 0x07;

// credProtect levels.
pub const CRED_PROT_UV_OPTIONAL: u64 = 0x01;
pub const CRED_PROT_UV_OPTIONAL_WITH_LIST: u64 = 0x02;
pub const CRED_PROT_UV_REQUIRED: u64 = 0x03;

/// Max credBlob length; also advertised by getInfo (0x0F).
pub const MAX_CREDBLOB_LENGTH: usize = 128;

// COSE algorithm identifiers. Negative per the COSE registry.
pub const ALG_ES256: i64 = -7;
pub const ALG_ES384: i64 = -35;
pub const ALG_ES512: i64 = -36;
pub const ALG_ES256K: i64 = -47;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_ECDH_ES_HKDF_256: i64 = -25; // clientPIN key agreement
// Curve-explicit aliases also accepted in pubKeyCredParams.
pub const ALG_ESP256: i64 = -9; // ECDSA-SHA256 P-256
pub const ALG_ED25519: i64 = -19; // EdDSA Ed25519
pub const ALG_ESP384: i64 = -51; // ECDSA-SHA384 P-384
pub const ALG_ESP512: i64 = -52; // ECDSA-SHA512 P-521

// ML-DSA (FIPS 204) COSE identifiers, from draft-ietf-cose-dilithium. Only
// ML-DSA-44 has an enabled backend; -49/-50 are recognized but unsupported.
pub const ALG_MLDSA44: i64 = -48;
pub const ALG_MLDSA65: i64 = -49;
pub const ALG_MLDSA87: i64 = -50;
/// COSE key type AKP (Algorithm Key Pair) — ML-DSA public keys: `{1:7, 3:alg, -1:pub}`.
pub const KTY_AKP: u8 = 7;

/// Prefer ML-DSA-44 whenever the platform offers it in `pubKeyCredParams`, even
/// listed after a classic alg — a deliberate deviation from CTAP's "first
/// supported" rule so an RP rolling out PQC need not reorder its preference
/// list for the classic-only installed base.
pub const PREFER_PQC: bool = true;

// FIDO curve identifiers, used inside COSE keys.
pub const CURVE_P256: u8 = 1;
pub const CURVE_P384: u8 = 2;
pub const CURVE_P521: u8 = 3;
pub const CURVE_ED25519: u8 = 6;
pub const CURVE_P256K1: u8 = 8;
/// Internal key-slot id for ML-DSA-44 credentials. Not a real COSE curve — AKP
/// keys have none — but the credential box stores `(alg, curve)` and `CredKey`
/// selects on `curve`, so the lattice scheme gets a private id well clear of
/// the registered EC ids (0x2C = 44).
pub const CURVE_MLDSA44: u8 = 0x2C;

// authenticatorData flag bits.
pub const FLAG_UP: u8 = 0x01; // user present
pub const FLAG_UV: u8 = 0x04; // user verified
pub const FLAG_AT: u8 = 0x40; // attested credential data included
pub const FLAG_ED: u8 = 0x80; // extension data included

/// AAGUID — RS-Key's own authenticator-model identifier (UUID **v5**), so the
/// device stops claiming pico-fido's model identity. Derived reproducibly as
/// `uuid5(NAMESPACE_URL, "https://github.com/TheMaxMur/RS-Key")`
/// = `2479c7bf-6b30-5683-9ec8-0e8171a918b7`. Self-assigned: an AAGUID needs no
/// central registration; FIDO MDS *listing* (a separate, certification-gated
/// step) is not required for the value itself. One AAGUID across every VID/PID
/// flavor — it identifies the firmware model, not the USB branding.
pub const AAGUID: [u8; 16] = [
    0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83, 0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9, 0x18, 0xB7,
];

/// firmwareVersion reported by getInfo (CTAP `0x0E`): the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] (default 5.7.4, `FW_VERSION`-overridable) in
/// Yubico's `(major << 16) | (minor << 8) | patch` form, so FIDO tooling
/// (`ykman` / Yubico Authenticator) reads a current YubiKey 5 version
/// consistent with the default YubiKey 5 VID/PID.
pub const FIRMWARE_VERSION: u32 = rsk_sdk::FIRMWARE_VERSION_U32;

// Size limits advertised by getInfo.
/// ML-DSA-44 responses run ~3.9 KB, so we advertise the full CTAPHID transport
/// maximum (57 + 128·59) end-to-end — every buffer on the path (reassembler,
/// worker exchange, applet response) holds this. `MAX_FRAGMENT_LENGTH` tracks
/// it per the spec's `maxMsgSize - 64`.
pub const MAX_MSG_SIZE: u64 = 7609;
pub const MAX_CRED_ID_LENGTH: u64 = 1024;
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 16;

/// Max serialized large-blob array stored; also the getInfo
/// `maxSerializedLargeBlobArray` (0x0B).
pub const MAX_LARGE_BLOB_SIZE: usize = 2048;
/// Max bytes per `authenticatorLargeBlobs` fragment.
pub const MAX_FRAGMENT_LENGTH: usize = MAX_MSG_SIZE as usize - 64;
/// Initial serialized large-blob array: the empty CBOR array `0x80` followed
/// by the left 16 bytes of its SHA-256 — the CTAP2.1 default value.
pub const LARGEBLOB_INITIAL: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];

/// Max resident credentials / relying parties.
pub const MAX_RESIDENT_CREDENTIALS: u16 = 256;

// FIDO flash file ids (device-local; fids never cross the wire).
// Audit journal (journal.rs) — deliberately outside every reset range: FIDO's
// authenticatorReset wipes an explicit set (reset.rs), PIV factory-reset wipes
// 0xD100..=0xD2FF; the journal survives both by construction.
pub const EF_AUDIT_META: u16 = 0xC100; // ver ‖ seq_next ‖ start ‖ epoch hash
pub const EF_AUDIT_RING: u16 = 0xC110; // entry slots, 0xC110..0xC110+AUDIT_RING_SLOTS
pub const AUDIT_RING_SLOTS: u32 = 128;
pub const EF_KEY_DEV: u16 = 0xCC00; // device master seed, encrypted
pub const EF_BACKUP_SEALED: u16 = 0xCC02; // [1] once the seed has been backed up
/// Soft-locked seed: ChaCha20-Poly1305(host lock key) over the seed value.
pub const EF_KEY_DEV_ENC: u16 = 0xCC03;
pub const EF_EE_DEV: u16 = 0xCE00; // U2F end-entity attestation certificate
// Org-provisioned attestation (vendor ATT_IMPORT). Device identity, not user
// data: both survive authenticatorReset; ATT_CLEAR removes them.
pub const EF_ATT_KEY: u16 = 0xCE10; // org attestation P-256 scalar, kbase-sealed
pub const EF_ATT_CHAIN: u16 = 0xCE11; // packed DER chain: count ‖ (len LE ‖ der)*
/// `enableEnterpriseAttestation` — persists until reset (CTAP 2.1), hence flash.
pub const EF_EA_ENABLED: u16 = 0xCE12;
pub const EF_COUNTER: u16 = 0xC000; // global signature counter
pub const EF_CRED: u16 = 0xCF00; // resident credentials, 0xCF00..0xCFFF
pub const EF_RP: u16 = 0xD000; // relying-party metadata, 0xD000..0xD0FF
pub const EF_PIN: u16 = 0x1080; // PIN: [retries, len, format, verifier(32)]
pub const EF_AUTHTOKEN: u16 = 0x1090; // pinUvAuthToken seed
pub const EF_PAUTHTOKEN: u16 = 0x1091; // persistent pinUvAuthToken seed
pub const EF_MINPINLEN: u16 = 0x1100; // minimum PIN length policy
pub const EF_LARGEBLOB: u16 = 0x1101; // serialized large-blob array

/// PIN retry budget.
pub const MAX_PIN_RETRIES: u8 = 8;
/// Default minimum PIN length when no policy is set.
#[cfg(not(feature = "fips-profile"))]
pub const MIN_PIN_LENGTH: u8 = 4;
/// The FIPS-style profile raises the PIN floor to six code points.
#[cfg(feature = "fips-profile")]
pub const MIN_PIN_LENGTH: u8 = 6;

// U2F authenticate control byte (P1) and flags.
pub const U2F_AUTH_ENFORCE: u8 = 0x03; // enforce user presence and sign
pub const U2F_AUTH_CHECK_ONLY: u8 = 0x07; // is this key handle ours?
pub const U2F_AUTH_FLAG_TUP: u8 = 0x01; // test-of-user-presence bit
pub const U2F_REGISTER_ID: u8 = 0x05; // registration response leading byte
