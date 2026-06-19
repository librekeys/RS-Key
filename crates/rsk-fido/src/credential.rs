// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Credential IDs. A CTAP2 credential ID is a self-contained ChaCha20-Poly1305
//! box: a CBOR map of the credential's metadata, encrypted under a key derived
//! from the device seed, with the rpId hash as AEAD associated data. Layout
//! (proto 0x02):
//!
//! ```text
//! proto(4 = f1d00202) ‖ iv(12) ‖ ciphertext ‖ poly1305_tag(16) ‖ silent_tag(16)
//! ```
//!
//! The silent tag binds the box to this device + rp without decrypting it.
//! Resident credentials additionally derive a 42-byte "resident id" that is what
//! the authenticator returns to the RP; the full box is kept in flash.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::{
    Device, chacha20poly1305_decrypt, chacha20poly1305_encrypt, hmac_sha256, hmac_sha512, sha256,
};
use rsk_fs::{Fs, Storage};
use rsk_sdk::error::{Error, Result};

use crate::consts::{
    ALG_ES256, CURVE_P256, EF_CRED, EF_RP, MAX_CREDBLOB_LENGTH, MAX_RESIDENT_CREDENTIALS,
};
use crate::keyderiv::{KEY_HANDLE_LEN, verify_key};

const CRED_PROTO: &[u8; 4] = b"\xf1\xd0\x02\x02";
const CRED_PROTO_RESIDENT: &[u8; 4] = b"\xf1\xd0\x02\x03";
/// Derive label for the EF_RP rpId box — domain-separated from the credential-id
/// protos so the rpId box key can never coincide with a cred-box key.
const RP_PROTO: &[u8] = b"RS-Key/EF_RP/rpId";
const PROTO_LEN: usize = 4;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SILENT_TAG_LEN: usize = 16;
/// Header before the ciphertext: proto + iv.
const HEAD_LEN: usize = PROTO_LEN + IV_LEN; // 16
/// Bytes around the ciphertext for proto 0x02: head + poly tag + silent tag.
const WRAP_LEN_22: usize = HEAD_LEN + TAG_LEN + SILENT_TAG_LEN; // 48

/// Resident-id length.
pub const CRED_RESIDENT_LEN: usize = 42;
const CRED_RESIDENT_HEADER_LEN: usize = 10;

/// Credential extensions sealed into the box. `minPinLength` is not stored —
/// it is a request-only flag that gates the authData `minPINLength` output.
#[derive(Clone, Copy, Default)]
pub struct CredExt<'a> {
    pub cred_protect: u64,
    pub cred_blob: &'a [u8],
    pub hmac_secret: bool,
    pub large_blob_key: bool,
    pub third_party_payment: bool,
}

impl CredExt<'_> {
    /// Whether this credBlob is short enough to seal (`< MAX_CREDBLOB_LENGTH`).
    fn cred_blob_ok(&self) -> bool {
        !self.cred_blob.is_empty() && self.cred_blob.len() < MAX_CREDBLOB_LENGTH
    }

    /// Number of entries the box's field-0x07 sub-map would carry.
    fn box_entries(&self) -> u64 {
        u64::from(self.cred_blob_ok())
            + u64::from(self.cred_protect != 0)
            + u64::from(self.hmac_secret)
            + u64::from(self.large_blob_key)
            + u64::from(self.third_party_payment)
    }
}

/// Inputs to [`credential_create`] — the request fields to seal into the box.
pub struct CredInput<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub use_sign_count: bool,
    pub rk: bool,
    pub created_ms: u64,
    /// COSE algorithm + FIDO curve (`CURVE_*`). Stored only when non-default
    /// (ES256/P-256), so existing P-256 boxes stay byte-identical.
    pub alg: i64,
    pub curve: i64,
    pub ext: CredExt<'a>,
}

/// A decrypted credential, borrowing the caller's scratch buffer.
pub struct Credential<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub use_sign_count: bool,
    pub rk: bool,
    pub alg: i64,
    pub curve: i64,
    /// Creation timestamp (device uptime) — getAssertion picks the newest match.
    pub created: u64,
    pub ext: CredExt<'a>,
    /// A U2F/CTAP1 key handle loaded via the [`credential_load`] fallback (no
    /// sealed body): getAssertion signs it with the path-as-is scalar
    /// ([`crate::keyderiv::verify_key`]), not the CTAP2 `fido_load_key` derivation.
    pub u2f: bool,
}

/// The box encryption key: a SLIP-0022 HMAC chain over the device seed.
fn derive_chacha_key(seed: &[u8; 32], proto: &[u8]) -> [u8; 32] {
    let mut k = hmac_sha256(seed, b"SLIP-0022");
    k = hmac_sha256(&k, proto);
    hmac_sha256(&k, b"Encryption key")
}

/// The silent tag: HMAC(SHA256(serial‖rpIdHash), prefix)[..16] where `prefix`
/// is the whole box except the silent tag.
///
/// Write-only: boxes are verified by decrypting (the chacha key comes from the
/// seed), never by this tag, so OTP-MKEK provisioning switching the tag source
/// from `serial_id` to `otp_key` cannot orphan old boxes. Any future change
/// that starts CHECKING the tag must accept both sources — pre-OTP credentials
/// carry serial-keyed tags.
fn silent_tag(dev: &Device, prefix: &[u8], rp_id_hash: &[u8; 32]) -> [u8; SILENT_TAG_LEN] {
    let src = dev.otp_key.map(|o| &o[..]).unwrap_or(dev.serial_id);
    let mut buf = [0u8; 64];
    buf[..src.len()].copy_from_slice(src);
    buf[src.len()..src.len() + 32].copy_from_slice(rp_id_hash);
    let k = sha256(&buf[..src.len() + 32]);
    let full = hmac_sha256(&k, prefix);
    let mut tag = [0u8; SILENT_TAG_LEN];
    tag.copy_from_slice(&full[..SILENT_TAG_LEN]);
    tag
}

/// Does this box carry the resident proto marker?
pub fn is_resident(data: &[u8]) -> bool {
    data.len() >= PROTO_LEN + 4 && &data[4..8] == CRED_PROTO_RESIDENT
}

/// Seal `input` into a credential box written to `out`. `iv` is
/// caller-supplied randomness. Returns the box length.
pub fn credential_create(
    seed: &[u8; 32],
    dev: &Device,
    input: &CredInput,
    rp_id_hash: &[u8; 32],
    iv: &[u8; IV_LEN],
    out: &mut [u8],
) -> Result<usize> {
    if out.len() < WRAP_LEN_22 {
        return Err(Error::NoMemory);
    }
    // Encode the inner CBOR straight into the ciphertext slot (out[16..]).
    let body_end = out.len() - TAG_LEN - SILENT_TAG_LEN;
    let rs = {
        let mut enc = Encoder::new(Cursor::new(&mut out[HEAD_LEN..body_end]));
        encode_body(&mut enc, input).map_err(|_| Error::NoMemory)?;
        enc.writer().position()
    };

    let mut key = derive_chacha_key(seed, CRED_PROTO);
    let tag = chacha20poly1305_encrypt(&key, iv, rp_id_hash, &mut out[HEAD_LEN..HEAD_LEN + rs]);
    key.zeroize();

    out[..PROTO_LEN].copy_from_slice(CRED_PROTO);
    out[PROTO_LEN..HEAD_LEN].copy_from_slice(iv);
    out[HEAD_LEN + rs..HEAD_LEN + rs + TAG_LEN].copy_from_slice(&tag);

    let prefix_len = HEAD_LEN + rs + TAG_LEN;
    let st = silent_tag(dev, &out[..prefix_len], rp_id_hash);
    out[prefix_len..prefix_len + SILENT_TAG_LEN].copy_from_slice(&st);
    Ok(prefix_len + SILENT_TAG_LEN)
}

fn encode_body<W: minicbor::encode::Write>(
    enc: &mut Encoder<W>,
    c: &CredInput,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    let ext_n = c.ext.box_entries();
    // alg/curve are stored only for non-default curves (P-256 boxes stay identical).
    let store_alg = c.curve != CURVE_P256 as i64;
    let mut n = 4u64; // rpId, userId, created, use_sign_count
    if !c.user_name.is_empty() {
        n += 1;
    }
    if !c.user_display_name.is_empty() {
        n += 1;
    }
    if ext_n > 0 {
        n += 1;
    }
    if store_alg {
        n += 2;
    }
    if c.rk {
        n += 1;
    }
    enc.map(n)?;
    enc.u8(1)?.str(c.rp_id)?;
    enc.u8(3)?.bytes(c.user_id)?;
    if !c.user_name.is_empty() {
        enc.u8(4)?.str(c.user_name)?;
    }
    if !c.user_display_name.is_empty() {
        enc.u8(5)?.str(c.user_display_name)?;
    }
    enc.u8(6)?.u64(c.created_ms)?;
    if ext_n > 0 {
        enc.u8(7)?.map(ext_n)?;
        if c.ext.cred_blob_ok() {
            enc.str("credBlob")?.bytes(c.ext.cred_blob)?;
        }
        if c.ext.cred_protect != 0 {
            enc.str("credProtect")?.u64(c.ext.cred_protect)?;
        }
        if c.ext.hmac_secret {
            enc.str("hmac-secret")?.bool(true)?;
        }
        if c.ext.large_blob_key {
            enc.str("largeBlobKey")?.bool(true)?;
        }
        if c.ext.third_party_payment {
            enc.str("thirdPartyPayment")?.bool(true)?;
        }
    }
    enc.u8(8)?.bool(c.use_sign_count)?;
    if store_alg {
        enc.u8(9)?.i64(c.alg)?;
        enc.u8(10)?.i64(c.curve)?;
    }
    if c.rk {
        enc.u8(11)?.bool(true)?;
    }
    Ok(())
}

/// Decrypt the box in place. `cred_id` is a caller-owned mutable copy; on
/// success its `[16..16+pt_len]` holds the plaintext. Returns the plaintext length.
fn verify_decrypt(seed: &[u8; 32], cred_id: &mut [u8], rp_id_hash: &[u8; 32]) -> Option<usize> {
    let len = cred_id.len();
    if len < HEAD_LEN + TAG_LEN {
        return None;
    }
    let is22 = &cred_id[..PROTO_LEN] == CRED_PROTO;
    let wrap = if is22 {
        WRAP_LEN_22
    } else {
        HEAD_LEN + TAG_LEN
    };
    if len < wrap {
        return None;
    }
    let ct_len = len - wrap;
    let mut proto = [0u8; PROTO_LEN];
    proto.copy_from_slice(&cred_id[..PROTO_LEN]);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&cred_id[PROTO_LEN..HEAD_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&cred_id[HEAD_LEN + ct_len..HEAD_LEN + ct_len + TAG_LEN]);

    let mut key = derive_chacha_key(seed, &proto);
    let res = chacha20poly1305_decrypt(
        &key,
        &iv,
        rp_id_hash,
        &mut cred_id[HEAD_LEN..HEAD_LEN + ct_len],
        &tag,
    );
    key.zeroize();
    res.ok()?;
    Some(ct_len)
}

/// Verify and parse a box into a [`Credential`] borrowing `scratch` (which
/// must be ≥ `cred_id.len()`).
pub fn credential_load<'a>(
    seed: &[u8; 32],
    cred_id: &[u8],
    rp_id_hash: &[u8; 32],
    scratch: &'a mut [u8],
) -> Option<Credential<'a>> {
    let n = cred_id.len();
    if n > scratch.len() {
        return None;
    }
    scratch[..n].copy_from_slice(cred_id);
    if let Some(pt_len) = verify_decrypt(seed, &mut scratch[..n], rp_id_hash) {
        return parse_body(&scratch[HEAD_LEN..HEAD_LEN + pt_len]);
    }
    // U2F fallback: a 64-byte path‖tag handle that verifies against this rp
    // loads as a minimal P-256 credential with no sealed body.
    if let Ok(kh) = <&[u8; KEY_HANDLE_LEN]>::try_from(cred_id)
        && verify_key(seed, rp_id_hash, kh).is_some()
    {
        return Some(Credential {
            rp_id: "",
            user_id: &[],
            user_name: "",
            user_display_name: "",
            use_sign_count: false,
            rk: false,
            alg: ALG_ES256,
            curve: CURVE_P256 as i64,
            created: 0,
            ext: CredExt::default(),
            u2f: true,
        });
    }
    None
}

fn parse_body(cbor: &[u8]) -> Option<Credential<'_>> {
    let mut d = Decoder::new(cbor);
    let mut cred = Credential {
        rp_id: "",
        user_id: &[],
        user_name: "",
        user_display_name: "",
        use_sign_count: false,
        rk: false,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        created: 0,
        ext: CredExt::default(),
        u2f: false,
    };
    let entries = d.map().ok()??;
    for _ in 0..entries {
        match d.u32().ok()? {
            1 => cred.rp_id = d.str().ok()?,
            3 => cred.user_id = d.bytes().ok()?,
            4 => cred.user_name = d.str().ok()?,
            5 => cred.user_display_name = d.str().ok()?,
            6 => cred.created = d.u64().ok()?,
            7 => {
                let m = d.map().ok()??;
                for _ in 0..m {
                    match d.str().ok()? {
                        "credProtect" => cred.ext.cred_protect = d.u64().ok()?,
                        "credBlob" => cred.ext.cred_blob = d.bytes().ok()?,
                        "hmac-secret" => cred.ext.hmac_secret = d.bool().ok()?,
                        "largeBlobKey" => cred.ext.large_blob_key = d.bool().ok()?,
                        "thirdPartyPayment" => cred.ext.third_party_payment = d.bool().ok()?,
                        _ => d.skip().ok()?,
                    }
                }
            }
            8 => cred.use_sign_count = d.bool().ok()?,
            9 => cred.alg = d.i64().ok()?,
            10 => cred.curve = d.i64().ok()?,
            11 => cred.rk = d.bool().ok()?,
            _ => d.skip().ok()?,
        }
    }
    Some(cred)
}

/// The 42-byte resident id returned to the RP for a resident credential.
/// Header = `serial-derived(4) ‖ proto23(4) ‖ 00 00`, then a 32-byte HMAC
/// chain over the box.
pub fn derive_resident(cred_id: &[u8], dev: &Device) -> [u8; CRED_RESIDENT_LEN] {
    let mut outk = [0u8; CRED_RESIDENT_LEN];
    let h0 = hmac_sha256(&[0u8; 32], dev.serial_id);
    outk[..32].copy_from_slice(&h0);
    outk[4..8].copy_from_slice(CRED_PROTO_RESIDENT);
    outk[8] = 0;
    outk[9] = 0;

    let mut cred_idr = [0u8; 32];
    cred_idr.copy_from_slice(&outk[CRED_RESIDENT_HEADER_LEN..]);
    cred_idr = hmac_sha256(&cred_idr, b"SLIP-0022");
    cred_idr = hmac_sha256(&cred_idr, &cred_id[..PROTO_LEN]);
    cred_idr = hmac_sha256(&cred_idr, b"resident");
    cred_idr = hmac_sha256(&cred_idr, cred_id);
    outk[CRED_RESIDENT_HEADER_LEN..].copy_from_slice(&cred_idr);
    outk
}

/// The 64-byte cred_random (`CredRandomWithUV ‖ CredRandomWithoutUV`) for the
/// hmac-secret extension — an HMAC-SHA512 ratchet over the device seed, keyed
/// each round by the previous output's first 32 bytes. The caller picks the UV
/// half: `[32..64]` with UV, `[0..32]` without.
pub fn derive_hmac_key(seed: &[u8; 32], cred_id: &[u8]) -> [u8; 64] {
    let proto = &cred_id[..PROTO_LEN.min(cred_id.len())];
    let mut k = hmac_sha512(seed, b"SLIP-0022");
    k = hmac_sha512(&k[..32], proto);
    k = hmac_sha512(&k[..32], b"hmac-secret");
    k = hmac_sha512(&k[..32], cred_id);
    k
}

/// The 32-byte largeBlobKey for a credential — an HMAC-SHA256 ratchet over the
/// device seed (same shape as the chacha key).
pub fn derive_large_blob_key(seed: &[u8; 32], cred_id: &[u8]) -> [u8; 32] {
    let proto = &cred_id[..PROTO_LEN.min(cred_id.len())];
    let mut k = hmac_sha256(seed, b"SLIP-0022");
    k = hmac_sha256(&k, proto);
    k = hmac_sha256(&k, b"largeBlobKey");
    k = hmac_sha256(&k, cred_id);
    k
}

/// A resident record is `rp_id_hash(32) ‖ resident_id(42) ‖ full_cred_id`.
pub const RECORD_PREFIX: usize = 32 + CRED_RESIDENT_LEN;

/// EF_RP head before the (boxed) rpId tail: `count(1) ‖ rpIdHash(32)`.
pub(crate) const RP_PREFIX: usize = 1 + 32;

/// Mark, in one storage pass, which slots `base+0..base+out.len()` hold a live
/// record (`out[i]` is occupied iff a key `base+i` exists). One pass is
/// O(items); per-slot `fs.read` probing is not — a `read` of an *absent* slot
/// rescans the whole flash partition. Callers still `fs.read` the occupied
/// slots — those reads hit the key cache.
pub(crate) fn slot_map<S: Storage>(fs: &mut Fs<S>, base: u16, out: &mut [bool]) {
    out.iter_mut().for_each(|b| *b = false);
    fs.for_each_key(&mut |fid| {
        if let Some(i) = fid.checked_sub(base)
            && (i as usize) < out.len()
        {
            out[i as usize] = true;
        }
    });
}

/// Persist a resident credential into a free or matching EF_CRED slot and bump
/// the EF_RP count.
pub fn credential_store<S: Storage>(
    seed: &[u8; 32],
    dev: &Device,
    fs: &mut Fs<S>,
    cred_id: &[u8],
    rp_id_hash: &[u8; 32],
    rp_id: &str,
    user_id: &[u8],
) -> Result<()> {
    let mut slot: Option<u16> = None;
    let mut new_record = true;
    let mut rec = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            if slot.is_none() {
                slot = Some(i);
            }
            continue;
        }
        let n = match fs.read(EF_CRED + i, &mut rec) {
            Some(n) if n > 0 => n.min(rec.len()),
            _ => continue,
        };
        if n < RECORD_PREFIX || rec[..32] != *rp_id_hash {
            continue;
        }
        if let Some(c) = credential_load(seed, &rec[RECORD_PREFIX..n], rp_id_hash, &mut scratch)
            && c.user_id == user_id
        {
            slot = Some(i);
            new_record = false;
            break;
        }
    }

    let slot = slot.ok_or(Error::NoMemory)?; // KEY_STORE_FULL
    let resident = derive_resident(cred_id, dev);
    let total = RECORD_PREFIX + cred_id.len();
    if total > rec.len() {
        return Err(Error::NoMemory);
    }
    rec[..32].copy_from_slice(rp_id_hash);
    rec[32..RECORD_PREFIX].copy_from_slice(&resident);
    rec[RECORD_PREFIX..total].copy_from_slice(cred_id);
    fs.put(EF_CRED + slot, &rec[..total])?;

    if new_record {
        bump_rp(fs, seed, rp_id_hash, rp_id)?;
    }
    Ok(())
}

/// Increment the credential count for an rp, creating its EF_RP record if new.
/// A new record's rpId domain is boxed under the device seed (see [`seal_rp_id`])
/// so a flash dump never reveals the cleartext list of relying parties; the
/// rpIdHash stays cleartext as the O(1) lookup key.
fn bump_rp<S: Storage>(
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    rp_id: &str,
) -> Result<()> {
    let mut rec = [0u8; 256];
    let mut free: Option<u16> = None;
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            if free.is_none() {
                free = Some(i);
            }
            continue;
        }
        let fid = EF_RP + i;
        if let Some(n) = fs.read(fid, &mut rec)
            && n >= RP_PREFIX
            && rec[1..RP_PREFIX] == *rp_id_hash
        {
            // Existing rp: bump the count, re-storing the boxed tail verbatim.
            let n = n.min(rec.len());
            rec[0] = rec[0].saturating_add(1);
            return fs.put(fid, &rec[..n]);
        }
    }
    let slot = free.ok_or(Error::NoMemory)?;
    rec[0] = 1;
    rec[1..RP_PREFIX].copy_from_slice(rp_id_hash);
    let blen = seal_rp_id(seed, rp_id, rp_id_hash, &mut rec[RP_PREFIX..])?;
    fs.put(EF_RP + slot, &rec[..RP_PREFIX + blen])
}

/// Box the rpId domain under the device seed. Layout written to `out`:
/// `iv(12) ‖ ciphertext ‖ poly1305_tag(16)`, ChaCha20-Poly1305 with the rpIdHash
/// as AAD. The IV is *deterministic* — there is exactly one EF_RP record per
/// rpIdHash and its plaintext (the domain) is immutable, so a fixed (key, iv)
/// never encrypts two different messages, which is the only thing nonce reuse
/// must avoid. Returns the box length.
pub(crate) fn seal_rp_id(
    seed: &[u8; 32],
    rp_id: &str,
    rp_id_hash: &[u8; 32],
    out: &mut [u8],
) -> Result<usize> {
    let id = rp_id.as_bytes();
    let total = IV_LEN + id.len() + TAG_LEN;
    if total > out.len() {
        return Err(Error::NoMemory);
    }
    let mut key = derive_chacha_key(seed, RP_PROTO);
    let iv_full = hmac_sha256(&key, rp_id_hash);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&iv_full[..IV_LEN]);
    out[..IV_LEN].copy_from_slice(&iv);
    out[IV_LEN..IV_LEN + id.len()].copy_from_slice(id);
    let tag = chacha20poly1305_encrypt(&key, &iv, rp_id_hash, &mut out[IV_LEN..IV_LEN + id.len()]);
    out[IV_LEN + id.len()..total].copy_from_slice(&tag);
    key.zeroize();
    Ok(total)
}

/// Recover the rpId domain from an EF_RP `tail`, whether it is a box (written by
/// [`seal_rp_id`]) or a legacy cleartext domain. The recovered string is written
/// into `out` and returned alongside a `was_boxed` flag (used by the boot
/// migration to decide whether to re-box). Trial-decryption distinguishes the
/// two formats: a cleartext domain fails the poly1305 check (probability of a
/// false positive ≈ 2⁻¹²⁸).
pub(crate) fn unseal_rp_id<'a>(
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    tail: &[u8],
    out: &'a mut [u8],
) -> Option<(&'a str, bool)> {
    let n = tail.len();
    // A box is iv(12) ‖ ct ‖ tag(16): at least 28 bytes, and it authenticates.
    if n >= IV_LEN + TAG_LEN && n <= out.len() {
        let ct_len = n - IV_LEN - TAG_LEN;
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&tail[..IV_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&tail[n - TAG_LEN..]);
        out[..ct_len].copy_from_slice(&tail[IV_LEN..IV_LEN + ct_len]);
        let mut key = derive_chacha_key(seed, RP_PROTO);
        let ok = chacha20poly1305_decrypt(&key, &iv, rp_id_hash, &mut out[..ct_len], &tag).is_ok();
        key.zeroize();
        if ok {
            return core::str::from_utf8(&out[..ct_len]).ok().map(|s| (s, true));
        }
    }
    // Legacy cleartext domain (the failed decrypt above left `out` garbled, so
    // re-copy the raw tail here).
    if n <= out.len() {
        out[..n].copy_from_slice(tail);
        return core::str::from_utf8(&out[..n]).ok().map(|s| (s, false));
    }
    None
}

/// Boot pass: re-box any legacy cleartext EF_RP record so a flash dump no longer
/// reveals the cleartext list of relying parties. Idempotent and crash-safe —
/// already-boxed records authenticate and are skipped, and a partially-migrated
/// set converges over boots. Must run after the keydev seed is readable under
/// the current root (i.e. after [`crate::seed::migrate_keydev_boot`]).
pub fn migrate_rp_seal<S: Storage>(dev: &Device, fs: &mut Fs<S>) {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    if !occupied.iter().any(|&b| b) {
        return; // no resident-cred RPs → nothing to seal, don't materialize the seed
    }
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return;
    };
    let mut buf = [0u8; 256];
    let mut plain = [0u8; 256];
    let mut out = [0u8; 256];
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let fid = EF_RP + i;
        let Some(n) = fs.read(fid, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RP_PREFIX {
            continue;
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&buf[1..RP_PREFIX]);
        let Some((domain, was_boxed)) =
            unseal_rp_id(&seed, &rp_id_hash, &buf[RP_PREFIX..n], &mut plain)
        else {
            continue;
        };
        if was_boxed {
            continue; // already sealed
        }
        out[0] = buf[0];
        out[1..RP_PREFIX].copy_from_slice(&rp_id_hash);
        if let Ok(blen) = seal_rp_id(&seed, domain, &rp_id_hash, &mut out[RP_PREFIX..]) {
            let _ = fs.put(fid, &out[..RP_PREFIX + blen]);
        }
    }
    seed.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    const SEED: [u8; 32] = [0x42; 32];
    const IV: [u8; 12] = [0x11; 12];

    fn input() -> CredInput<'static> {
        CredInput {
            rp_id: "example.com",
            user_id: &[0xDE, 0xAD, 0xBE, 0xEF],
            user_name: "alice",
            user_display_name: "Alice Smith",
            use_sign_count: true,
            rk: false,
            created_ms: 12345,
            alg: ALG_ES256,
            curve: CURVE_P256 as i64,
            ext: CredExt::default(),
        }
    }

    #[test]
    fn create_load_roundtrip() {
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
        assert_eq!(&out[..4], CRED_PROTO);

        let mut scratch = [0u8; 512];
        let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.user_id, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(c.user_name, "alice");
        assert_eq!(c.user_display_name, "Alice Smith");
        assert!(c.use_sign_count);
        assert_eq!(c.alg, ALG_ES256);
        assert_eq!(c.curve, CURVE_P256 as i64);
    }

    #[test]
    fn non_p256_alg_curve_roundtrip() {
        use crate::consts::{ALG_ES512, CURVE_P521};
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let mut inp = input();
        inp.alg = ALG_ES512;
        inp.curve = CURVE_P521 as i64;
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
        let mut scratch = [0u8; 512];
        let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
        assert_eq!(c.alg, ALG_ES512);
        assert_eq!(c.curve, CURVE_P521 as i64);
    }

    #[test]
    fn extensions_roundtrip_through_box() {
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let mut inp = input();
        inp.rk = true;
        inp.ext = CredExt {
            cred_protect: 2,
            cred_blob: &[0xBE, 0xEF, 0x42],
            hmac_secret: true,
            large_blob_key: true,
            third_party_payment: true,
        };
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();

        let mut scratch = [0u8; 512];
        let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
        assert_eq!(c.ext.cred_protect, 2);
        assert_eq!(c.ext.cred_blob, &[0xBE, 0xEF, 0x42]);
        assert!(c.ext.hmac_secret);
        assert!(c.ext.large_blob_key);
        assert!(c.ext.third_party_payment);
        assert!(c.rk);
    }

    #[test]
    fn oversized_cred_blob_is_dropped() {
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let big = [0u8; MAX_CREDBLOB_LENGTH + 1];
        let mut inp = input();
        inp.ext.cred_blob = &big;
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
        let mut scratch = [0u8; 512];
        let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
        assert!(
            c.ext.cred_blob.is_empty(),
            "oversized credBlob is not sealed"
        );
    }

    #[test]
    fn wrong_rp_hash_fails_to_decrypt() {
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
        let other = sha256(b"evil.com");
        let mut scratch = [0u8; 512];
        assert!(credential_load(&SEED, &out[..len], &other, &mut scratch).is_none());
    }

    #[test]
    fn tampered_box_fails() {
        let d = dev();
        let rp_hash = sha256(b"example.com");
        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
        out[HEAD_LEN] ^= 0x01; // flip a ciphertext byte
        let mut scratch = [0u8; 512];
        assert!(credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).is_none());
    }

    #[test]
    fn hmac_key_deterministic_uv_halves_differ() {
        let box1 = [0x55u8; 80];
        let mut box2 = box1;
        box2[40] ^= 0xFF;
        let k1 = derive_hmac_key(&SEED, &box1);
        assert_eq!(k1, derive_hmac_key(&SEED, &box1), "deterministic");
        // The CredRandomWithUV ([32..64]) and CredRandomWithoutUV ([0..32]) differ.
        assert_ne!(&k1[..32], &k1[32..]);
        // A different box yields a different cred_random.
        assert_ne!(k1, derive_hmac_key(&SEED, &box2));
        // The proto prefix (first 4 bytes) is folded in, so it is path-sensitive.
        assert_ne!(
            derive_hmac_key(&SEED, &box1),
            derive_hmac_key(&[0x43; 32], &box1)
        );
    }

    #[test]
    fn large_blob_key_deterministic_and_box_sensitive() {
        let box1 = [0x55u8; 80];
        let mut box2 = box1;
        box2[10] ^= 0xFF;
        let k1 = derive_large_blob_key(&SEED, &box1);
        assert_eq!(k1, derive_large_blob_key(&SEED, &box1));
        assert_ne!(k1, derive_large_blob_key(&SEED, &box2));
        assert_ne!(k1, derive_hmac_key(&SEED, &box1)[..32]);
    }

    #[test]
    fn resident_id_format_and_determinism() {
        let d = dev();
        let cred_id = [0x55u8; 80];
        let r1 = derive_resident(&cred_id, &d);
        let r2 = derive_resident(&cred_id, &d);
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), CRED_RESIDENT_LEN);
        assert_eq!(&r1[4..8], CRED_PROTO_RESIDENT);
        assert!(is_resident(&r1));
    }

    #[test]
    fn store_then_dedup_and_rp_count() {
        let d = dev();
        let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new(), &[]);
        let rp_hash = sha256(b"example.com");

        let mut out = [0u8; 512];
        let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
        credential_store(
            &SEED,
            &d,
            &mut fs,
            &out[..len],
            &rp_hash,
            "example.com",
            &[0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();

        // Stored in the first EF_CRED slot, record = rp_hash ‖ resident ‖ box.
        assert!(fs.has_data(EF_CRED));
        let mut rec = [0u8; 1024];
        let n = fs.read(EF_CRED, &mut rec).unwrap();
        assert_eq!(&rec[..32], &rp_hash[..]);
        assert_eq!(n, RECORD_PREFIX + len);
        // EF_RP created with count 1.
        let mut rp = [0u8; 256];
        let m = fs.read(EF_RP, &mut rp).unwrap();
        assert_eq!(rp[0], 1);
        assert_eq!(&rp[1..33], &rp_hash[..]);
        // The rpId domain tail is boxed under the seed: not cleartext on flash,
        // but it un-boxes back to the original domain.
        assert_ne!(&rp[RP_PREFIX..m], b"example.com");
        let mut scratch = [0u8; 256];
        let (domain, was_boxed) =
            unseal_rp_id(&SEED, &rp_hash, &rp[RP_PREFIX..m], &mut scratch).unwrap();
        assert_eq!(domain, "example.com");
        assert!(was_boxed);

        // Re-registering the SAME user reuses the slot (no new RP record / count bump).
        let iv2 = [0x22u8; 12];
        let len2 = credential_create(&SEED, &d, &input(), &rp_hash, &iv2, &mut out).unwrap();
        credential_store(
            &SEED,
            &d,
            &mut fs,
            &out[..len2],
            &rp_hash,
            "example.com",
            &[0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();
        assert!(!fs.has_data(EF_CRED + 1)); // still one credential slot used
        let m2 = fs.read(EF_RP, &mut rp).unwrap();
        assert_eq!(rp[0], 1, "same user must not bump the rp count");
        assert_eq!(m2, m);
    }
}
