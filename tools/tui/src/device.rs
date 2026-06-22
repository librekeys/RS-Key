// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Native device I/O for rsk-tui — FIDO CTAPHID over hidapi and the CCID applets
//! over PC/SC. No external processes: the TUI talks to the key directly.
//!
//! The dashboard reads (getInfo, vendor/rescue status, applet presence) are
//! unauthenticated. The seed backup (export/restore) implements the full MSE
//! channel (P-256 ECDH -> HKDF -> ChaCha20-Poly1305) and, when a PIN is set, the
//! clientPIN protocol-two pinUvAuthToken (ECDH -> HKDF -> AES-CBC + HMAC) +
//! BIP-39 — all in Rust, no `rsk` shell-out. SLIP-39 and the picotool/BOOTSEL
//! fuse rituals stay in the CLI.
//!
//! Everything device-facing is funneled through the [`DeviceProvider`] trait so
//! the UI can be driven by a [`MockProvider`] with no hardware (`--demo`).

use aes::Aes256;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ciborium::value::{Integer, Value};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use pcsc::{Context, Protocols, Scope, ShareMode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::model::*;

const REPORT_LEN: usize = 64;
const CTAPHID_INIT: u8 = 0x86;
const CTAPHID_CBOR: u8 = 0x90;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const CTAP_VENDOR: u8 = 0x41;
const PERM_ACFG: i64 = 0x20;

const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];
const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];
const OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

// Vendor subcommands (CTAP_VENDOR).
const VENDOR_STATE: u8 = 5;
const VENDOR_ATT_STATE: u8 = 11;
const VENDOR_AUDIT_READ: u8 = 7;
const VENDOR_AUDIT_CHECKPOINT: u8 = 8;

const AUDIT_ENTRY_LEN: usize = 20;
const CKPT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

pub const COLORS: [&str; 8] = [
    "off", "red", "green", "blue", "yellow", "magenta", "cyan", "white",
];

const AUDIT_EVENTS: &[(u8, &str)] = &[
    (0x01, "BOOT"),
    (0x02, "MAKE_CREDENTIAL"),
    (0x03, "GET_ASSERTION"),
    (0x04, "RESET"),
    (0x05, "PIN_SET"),
    (0x06, "PIN_CHANGE"),
    (0x07, "PIN_LOCKOUT"),
    (0x08, "CFG_MIN_PIN"),
    (0x09, "CFG_ENTERPRISE_ATT"),
    (0x0A, "LOCK_ENGAGE"),
    (0x0B, "LOCK_RELEASE"),
    (0x0C, "BACKUP_EXPORT"),
    (0x0D, "BACKUP_LOAD"),
    (0x0E, "BACKUP_FINALIZE"),
    (0x0F, "U2F_REGISTER"),
    (0x10, "U2F_AUTH"),
    (0x11, "CHECKPOINT"),
    (0x12, "ATT_IMPORT"),
    (0x13, "ATT_CLEAR"),
];

fn event_name(t: u8) -> String {
    AUDIT_EVENTS
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| format!("0x{t:02x}"))
}

// ===========================================================================
// Provider abstraction — the only surface the app talks to.
// ===========================================================================

/// Everything the cockpit can ask of a device. Implemented by
/// [`HardwareProvider`] (real I/O) and [`MockProvider`] (`--demo`).
pub trait DeviceProvider {
    fn snapshot(&mut self) -> DeviceSnapshot;
    /// Run a (non-Refresh) action. The caller has already collected any inputs.
    fn run(&mut self, action: Action, input: &ActionInput) -> ActionResult;
}

/// Talks to a real key over hidapi + PC/SC.
#[derive(Default)]
pub struct HardwareProvider;

impl DeviceProvider for HardwareProvider {
    fn snapshot(&mut self) -> DeviceSnapshot {
        snapshot()
    }

    fn run(&mut self, action: Action, input: &ActionInput) -> ActionResult {
        let pin = input.pin.as_deref().map(String::as_str);
        match action {
            // Refresh is handled by the caller (it just re-snapshots).
            Action::Refresh => ActionResult::Ok("status refreshed".into()),
            Action::LedGet => match led_get() {
                Ok(s) => ActionResult::Report {
                    title: "LED state".into(),
                    body: s,
                },
                Err(e) => ActionResult::Failed(format!("LED read failed: {e}")),
            },
            Action::LedCycle => match led_cycle_idle() {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("LED set failed: {e}")),
            },
            Action::RebootApp => match reboot(false) {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("reboot failed: {e}")),
            },
            Action::RebootBootsel => match reboot(true) {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("reboot failed: {e}")),
            },
            Action::BackupExport => match backup_export(pin) {
                Ok(words) => ActionResult::Reveal {
                    title: "seed · BIP-39 (24 words)".into(),
                    body: Zeroizing::new(words),
                },
                Err(e) => ActionResult::Failed(format!("export failed: {e}")),
            },
            Action::BackupRestore => {
                let phrase = input.phrase.as_deref().map(String::as_str).unwrap_or("");
                match backup_restore(phrase, pin) {
                    Ok(s) => ActionResult::Ok(s),
                    Err(e) => ActionResult::Failed(format!("restore failed: {e}")),
                }
            }
            Action::BackupFinalize => match backup_finalize() {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("finalize failed: {e}")),
            },
            Action::AuditRead => match audit_read(pin) {
                Ok((title, body)) => ActionResult::Report { title, body },
                Err(e) => ActionResult::Failed(format!("audit read failed: {e}")),
            },
            Action::Verify => match verify_identity(pin) {
                Ok((title, body)) => ActionResult::Report { title, body },
                Err(e) => ActionResult::Failed(format!("verify failed: {e}")),
            },
        }
    }
}

// ===========================================================================
// FIDO CTAPHID (hidapi)
// ===========================================================================

/// Open the FIDO HID device, also returning its bcdDevice + product string.
fn hid_open_info() -> Option<(hidapi::HidDevice, u16, Option<String>)> {
    let api = hidapi::HidApi::new().ok()?;
    let info = api
        .device_list()
        .find(|d| d.usage_page() == FIDO_USAGE_PAGE)?;
    let bcd = info.release_number();
    let product = info.product_string().map(str::to_string);
    let dev = info.open_device(&api).ok()?;
    Some((dev, bcd, product))
}

fn hid_open() -> Option<hidapi::HidDevice> {
    hid_open_info().map(|(d, _, _)| d)
}

fn hid_write(dev: &hidapi::HidDevice, frame: &[u8]) {
    let mut buf = [0u8; REPORT_LEN + 1];
    let n = frame.len().min(REPORT_LEN);
    buf[1..1 + n].copy_from_slice(&frame[..n]);
    let _ = dev.write(&buf);
}

fn hid_read(dev: &hidapi::HidDevice, ms: i32) -> Vec<u8> {
    let mut buf = [0u8; REPORT_LEN];
    match dev.read_timeout(&mut buf, ms) {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

fn ctaphid_init(dev: &hidapi::HidDevice) -> Option<[u8; 4]> {
    let mut f = vec![0xff, 0xff, 0xff, 0xff, CTAPHID_INIT, 0, 8];
    f.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    hid_write(dev, &f);
    let r = hid_read(dev, 2000);
    if r.len() < 19 || r[4] != CTAPHID_INIT {
        return None;
    }
    Some([r[15], r[16], r[17], r[18]])
}

/// Send a CTAP2 CBOR command and return the raw response (status byte + payload).
/// `ms` is the per-frame read timeout — long for touch-gated ops.
fn send_cbor(dev: &hidapi::HidDevice, cid: [u8; 4], payload: &[u8], ms: i32) -> Vec<u8> {
    let n = payload.len();
    let mut f = cid.to_vec();
    f.extend_from_slice(&[CTAPHID_CBOR, (n >> 8) as u8, (n & 0xff) as u8]);
    f.extend_from_slice(&payload[..n.min(57)]);
    hid_write(dev, &f);
    let (mut off, mut seq) = (57usize, 0u8);
    while off < n {
        let mut c = cid.to_vec();
        c.push(seq);
        let end = (off + 59).min(n);
        c.extend_from_slice(&payload[off..end]);
        hid_write(dev, &c);
        off = end;
        seq = seq.wrapping_add(1);
    }
    let mut r = hid_read(dev, ms);
    while r.len() >= 5 && r[4] == 0xBB {
        r = hid_read(dev, ms); // CTAPHID_KEEPALIVE (UP wait)
    }
    if r.len() < 7 {
        return Vec::new();
    }
    let bcnt = ((r[5] as usize) << 8) | r[6] as usize;
    let mut data = r[7..(7 + bcnt).min(r.len())].to_vec();
    while data.len() < bcnt {
        let c = hid_read(dev, ms);
        if c.len() < 6 {
            break;
        }
        let take = (bcnt - data.len()).min(59).min(c.len() - 5);
        data.extend_from_slice(&c[5..5 + take]);
    }
    data.truncate(bcnt);
    data
}

/// Encode + send a vendor (0x41) command and decode the CBOR response map.
/// Returns `(status, value)`.
fn vendor(dev: &hidapi::HidDevice, cid: [u8; 4], req: Value, ms: i32) -> (u8, Option<Value>) {
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&req));
    let r = send_cbor(dev, cid, &payload, ms);
    match r.first() {
        Some(0) => (0, ciborium::de::from_reader(&r[1..]).ok()),
        Some(s) => (*s, None),
        None => (0xFF, None),
    }
}

// ===========================================================================
// CBOR helpers
// ===========================================================================

fn iv(n: i64) -> Value {
    Value::Integer(Integer::from(n))
}

fn cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("cbor encode");
    out
}

fn cose_key(x: &[u8], y: &[u8]) -> Value {
    Value::Map(vec![
        (iv(1), iv(2)),
        (iv(3), iv(-25)),
        (iv(-1), iv(1)),
        (iv(-2), Value::Bytes(x.to_vec())),
        (iv(-3), Value::Bytes(y.to_vec())),
    ])
}

fn map_get(v: &Value, key: i128) -> Option<&Value> {
    if let Value::Map(m) = v {
        for (k, val) in m {
            if let Value::Integer(i) = k
                && i128::from(*i) == key
            {
                return Some(val);
            }
        }
    }
    None
}

fn as_u32(v: &Value) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(i128::from(*i)).ok()
    } else {
        None
    }
}

// ===========================================================================
// crypto primitives (HW-verified — do not alter the algorithm)
// ===========================================================================

fn ecdh_pub() -> (SecretKey, [u8; 32], [u8; 32]) {
    let sk = SecretKey::random(&mut OsRng);
    let ep = sk.public_key().to_encoded_point(false);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    x.copy_from_slice(ep.x().unwrap());
    y.copy_from_slice(ep.y().unwrap());
    (sk, x, y)
}

fn ecdh_raw(sk: &SecretKey, px: &[u8; 32], py: &[u8; 32]) -> Option<[u8; 32]> {
    let ep = EncodedPoint::from_affine_coordinates(px.into(), py.into(), false);
    let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&ep))?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut z = [0u8; 32];
    z.copy_from_slice(shared.raw_secret_bytes());
    Some(z)
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("hkdf");
    okm
}

fn hmac256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn aes_cbc_encrypt(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let mut buf = pt.to_vec();
    let n = buf.len();
    cbc::Encryptor::<Aes256>::new_from_slices(key, &iv)
        .unwrap()
        .encrypt_padded_mut::<NoPadding>(&mut buf, n)
        .unwrap();
    let mut out = iv.to_vec();
    out.extend_from_slice(&buf);
    out
}

fn aes_cbc_decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 {
        return None;
    }
    let (iv, ct) = data.split_at(16);
    let mut buf = ct.to_vec();
    let pt = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .ok()?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .ok()?;
    Some(pt.to_vec())
}

fn chacha_decrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .ok()?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn chacha_encrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .unwrap()
}

// ===========================================================================
// snapshot — the unauthenticated reads that fill the dashboard
// ===========================================================================

/// Gather the full device snapshot over both transports. Every channel is
/// probed softly: an absent or erroring channel is recorded, never fatal.
pub fn snapshot() -> DeviceSnapshot {
    let mut snap = DeviceSnapshot::default();
    read_fido(&mut snap);
    read_ccid(&mut snap);
    snap
}

fn read_fido(snap: &mut DeviceSnapshot) {
    let Some((dev, bcd, product)) = hid_open_info() else {
        snap.transport.hid = Link::Absent;
        return;
    };
    snap.transport.hid = Link::Present;
    snap.fido.present = true;
    snap.identity.bcd_device = Some(bcd);
    snap.identity.product = product;

    let Some(cid) = ctaphid_init(&dev) else {
        snap.transport.hid = Link::Error;
        snap.errors.push("CTAPHID init failed".into());
        return;
    };

    let gi = send_cbor(&dev, cid, &[0x04], 2000);
    if gi.first() == Some(&0)
        && let Ok(v) = ciborium::de::from_reader::<Value, _>(&gi[1..])
    {
        if let Some(Value::Array(a)) = map_get(&v, 1) {
            snap.fido.versions = a
                .iter()
                .filter_map(|x| x.as_text().map(String::from))
                .collect();
        }
        if let Some(Value::Integer(i)) = map_get(&v, 14) {
            let n = i128::from(*i) as u32;
            snap.identity.firmware = Some(format!(
                "{}.{}.{}",
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            ));
        }
        if let Some(Value::Bytes(b)) = map_get(&v, 3) {
            snap.identity.aaguid = Some(b.iter().map(|x| format!("{x:02x}")).collect());
        }
        if let Some(Value::Map(opts)) = map_get(&v, 4) {
            for (k, val) in opts {
                if let Some(name) = k.as_text() {
                    if name == "clientPin" {
                        snap.fido.client_pin = val.as_bool();
                    }
                    if val.as_bool() == Some(true) {
                        snap.fido.options.push(name.to_string());
                    }
                }
            }
            snap.fido.options.sort();
        }
    }

    // Vendor STATE — backup + soft-lock.
    if let (0, Some(v)) = vendor(
        &dev,
        cid,
        Value::Map(vec![(iv(1), iv(VENDOR_STATE as i64))]),
        2000,
    ) {
        snap.backup = Some(BackupState {
            sealed: map_get(&v, 1).and_then(Value::as_bool).unwrap_or(false),
            has_seed: map_get(&v, 2).and_then(Value::as_bool).unwrap_or(false),
        });
        if let (Some(locked), Some(unlocked)) = (
            map_get(&v, 3).and_then(Value::as_bool),
            map_get(&v, 4).and_then(Value::as_bool),
        ) {
            snap.lock = Some(LockState { locked, unlocked });
        }
    }

    // Vendor ATT_STATE — org attestation.
    if let (0, Some(v)) = vendor(
        &dev,
        cid,
        Value::Map(vec![(iv(1), iv(VENDOR_ATT_STATE as i64))]),
        2000,
    ) {
        let installed = map_get(&v, 1).and_then(Value::as_bool).unwrap_or(false);
        let chain = match map_get(&v, 2) {
            Some(Value::Bytes(b)) if installed => {
                Some(b.iter().map(|x| format!("{x:02x}")).collect())
            }
            _ => None,
        };
        snap.attestation = Some(AttestationState {
            installed,
            chain_sha256: chain,
        });
    }
}

fn read_ccid(snap: &mut DeviceSnapshot) {
    let ctx = match Context::establish(Scope::User) {
        Ok(c) => c,
        Err(_) => {
            snap.transport.pcsc = Link::Absent;
            return;
        }
    };
    let mut names = [0u8; 2048];
    let readers: Vec<&std::ffi::CStr> = match ctx.list_readers(&mut names) {
        Ok(r) => r.collect(),
        Err(_) => {
            snap.transport.pcsc = Link::Error;
            return;
        }
    };
    if readers.is_empty() {
        snap.transport.pcsc = Link::Absent;
        return;
    }
    snap.transport.pcsc = Link::Present;
    let target = readers
        .iter()
        .find(|r| {
            // Default build's product carries "RS-Key"; the opt-in Yubico interop
            // flavor carries "RSK". Neither is in a genuine YubiKey's reader name.
            let n = r.to_string_lossy();
            n.contains("RS-Key") || n.contains("RSK")
        })
        .copied()
        .unwrap_or(readers[0]);
    let card = match ctx.connect(target, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(e) => {
            snap.transport.ccid = Link::Busy;
            snap.transport.note = Some(format!("CCID reader busy? ({e})"));
            return;
        }
    };
    let mut ccid = Ccid {
        card,
        buf: [0u8; 1024],
    };

    // Rescue applet: identity + secure boot + rollback + flash.
    if ccid.select(RESCUE_AID).is_ok() {
        snap.transport.ccid = Link::Present;
        if let Ok((d, 0x90, 0x00)) = ccid.apdu_select(RESCUE_AID)
            && d.len() >= 12
        {
            snap.identity.serial = Some(d[4..12].iter().map(|b| format!("{b:02x}")).collect());
            snap.identity.sdk = Some(format!("{}.{}", d[2], d[3]));
        }
        if let Ok((d, 0x90, 0x00)) = ccid.apdu(&[0x80, 0x1E, 0x03, 0x00, 0x00])
            && d.len() >= 3
        {
            snap.secure_boot = Some(SecureBootState {
                enabled: d[0] != 0,
                locked: d[1] != 0,
                bootkey: d[2],
            });
        }
        if let Ok((d, 0x90, 0x00)) = ccid.apdu(&[0x80, 0x1E, 0x06, 0x00, 0x00])
            && d.len() >= 3
        {
            snap.rollback = Some(RollbackState {
                required: d[0] != 0,
                version: d[1],
                capacity: d[2],
            });
        }
        if let Ok((d, 0x90, 0x00)) = ccid.apdu(&[0x80, 0x1E, 0x02, 0x00, 0x00])
            && d.len() >= 20
        {
            snap.flash = Some(FlashState {
                free: u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                used: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
                kv_total: u32::from_be_bytes([d[8], d[9], d[10], d[11]]),
                files: u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
                chip: u32::from_be_bytes([d[16], d[17], d[18], d[19]]),
            });
        }
    } else {
        snap.transport.ccid = Link::Error;
    }

    // Applet presence — a plain SELECT is a read with no state change.
    snap.applets.openpgp = Some(ccid.select(OPENPGP_AID).is_ok());
    snap.applets.piv = Some(ccid.select(PIV_AID).is_ok());
    snap.applets.oath = Some(ccid.select(OATH_AID).is_ok());
    snap.applets.otp = Some(ccid.select(OTP_AID).is_ok());
}

// ===========================================================================
// CCID applets (PC/SC)
// ===========================================================================

struct Ccid {
    card: pcsc::Card,
    buf: [u8; 1024],
}

impl Ccid {
    fn open() -> Result<Self, String> {
        let ctx = Context::establish(Scope::User).map_err(|e| format!("pcsc: {e}"))?;
        let mut names = [0u8; 2048];
        let readers: Vec<&std::ffi::CStr> = ctx
            .list_readers(&mut names)
            .map_err(|e| format!("readers: {e}"))?
            .collect();
        if readers.is_empty() {
            return Err("no PC/SC readers".into());
        }
        let target = readers
            .iter()
            .find(|r| {
                // Default build's product carries "RS-Key"; the opt-in Yubico interop
                // flavor carries "RSK". Neither is in a genuine YubiKey's reader name.
                let n = r.to_string_lossy();
                n.contains("RS-Key") || n.contains("RSK")
            })
            .copied()
            .unwrap_or(readers[0]);
        let card = ctx
            .connect(target, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| format!("connect (reader busy?): {e}"))?;
        Ok(Ccid {
            card,
            buf: [0u8; 1024],
        })
    }

    fn apdu(&mut self, data: &[u8]) -> Result<(Vec<u8>, u8, u8), String> {
        let r = self
            .card
            .transmit(data, &mut self.buf)
            .map_err(|e| format!("transmit: {e}"))?;
        if r.len() < 2 {
            return Err("short response".into());
        }
        Ok((r[..r.len() - 2].to_vec(), r[r.len() - 2], r[r.len() - 1]))
    }

    /// SELECT an applet, returning the full response (data + status).
    fn apdu_select(&mut self, aid: &[u8]) -> Result<(Vec<u8>, u8, u8), String> {
        let mut a = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        a.extend_from_slice(aid);
        a.push(0x00);
        self.apdu(&a)
    }

    fn select(&mut self, aid: &[u8]) -> Result<(), String> {
        let (_, s1, s2) = self.apdu_select(aid)?;
        if (s1, s2) != (0x90, 0x00) {
            return Err(format!("SELECT failed {s1:02X}{s2:02X}"));
        }
        Ok(())
    }
}

// ===========================================================================
// LED / reboot (native, unauthenticated)
// ===========================================================================

pub fn led_get() -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let (d, s1, s2) = c.apdu(&[0x00, 0x11, 0x00, 0x00, 0x00])?;
    if (s1, s2) != (0x90, 0x00) || d.len() < 9 {
        return Err(format!("GET LED {s1:02X}{s2:02X}"));
    }
    let stride = if d.len() >= 17 {
        4
    } else if d.len() >= 13 {
        3
    } else {
        2
    };
    let names = ["idle", "processing", "touch", "boot"];
    let effect_names = ["legacy", "vapor", "bounce", "flow", "sparkle"];
    let mut out = format!("mode = {}\n", if d[0] != 0 { "steady" } else { "blink" });
    for (i, name) in names.iter().enumerate() {
        let off = 1 + i * stride;
        // stride=2: [color, brightness]; stride>=3: [effect, color, brightness, …]
        let (color, brightness) = if stride >= 3 {
            (d[off + 1], d[off + 2])
        } else {
            (d[off], d[off + 1])
        };
        let effect = if stride >= 3 {
            format!(
                " effect={}",
                effect_names.get(d[off] as usize).copied().unwrap_or("?")
            )
        } else {
            String::new()
        };
        out += &format!(
            "{name:<11} {}  (brightness {}){}\n",
            COLORS.get(color as usize).copied().unwrap_or("?"),
            brightness,
            effect,
        );
    }
    Ok(out)
}

pub fn led_cycle_idle() -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let (d, s1, s2) = c.apdu(&[0x00, 0x11, 0x00, 0x00, 0x00])?;
    if (s1, s2) != (0x90, 0x00) || d.len() < 9 {
        return Err(format!("GET LED {s1:02X}{s2:02X}"));
    }
    let stride = if d.len() >= 17 {
        4
    } else if d.len() >= 13 {
        3
    } else {
        2
    };
    // idle status: color/brightness offset depends on stride.
    let (idle_color, idle_brightness) = if stride >= 3 {
        (d[2], d[3]) // [steady, (effect, color, brightness, …), …]
    } else {
        (d[1], d[2]) // [steady, (color, brightness), …]
    };
    let next = ((idle_color as usize) % 7) + 1;
    let brightness = if idle_brightness == 0 {
        16
    } else {
        idle_brightness
    };
    let p2 = (next as u8 & 0x7) | if d[0] != 0 { 0x08 } else { 0 };
    let (_, s1, s2) = c.apdu(&[0x00, 0x10, brightness, p2])?;
    if (s1, s2) != (0x90, 0x00) {
        return Err(format!("SET LED {s1:02X}{s2:02X}"));
    }
    Ok(format!("idle color → {}", COLORS[next]))
}

pub fn reboot(bootsel: bool) -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let _ = c.apdu(&[0x00, 0x1F, if bootsel { 0x01 } else { 0x00 }, 0x00, 0x00]);
    Ok(format!(
        "reboot → {} sent",
        if bootsel { "BOOTSEL" } else { "app" }
    ))
}

// ===========================================================================
// audit journal (read) + identity verify (signed checkpoint)
// ===========================================================================

/// Read the tamper-evident journal (vendor AUDIT_READ). Read-only; the device
/// asks for a PIN if one is set. Returns `(title, pretty body)`.
pub fn audit_read(pin: Option<&str>) -> Result<(String, String), String> {
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;

    let mut req = vec![(iv(1), iv(VENDOR_AUDIT_READ as i64))];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_AUDIT_READ, &[]) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, v) = vendor(&dev, cid, Value::Map(req), 5000);
    match st {
        0 => {}
        0x36 => return Err("device requires a PIN (set one and retry)".into()),
        s => return Err(format!("status {s:#x}")),
    }
    let v = v.ok_or("decode failed")?;
    let start = map_get(&v, 1).and_then(as_u32).ok_or("no start")?;
    let seq_next = map_get(&v, 2).and_then(as_u32).ok_or("no seq")?;
    let epoch = match map_get(&v, 3) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no epoch".into()),
    };
    let entries = match map_get(&v, 4) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no entries".into()),
    };

    let head = fold(&epoch, &entries);
    let count = entries.len() / AUDIT_ENTRY_LEN;
    let mut body = format!(
        "window [{start}, {seq_next})  —  {count} entries, {start} folded into the epoch\n\
         epoch : {}\n\
         head  : {}  (chain over the window)\n\n",
        hex(&epoch),
        hex(&head),
    );
    // Show the most recent entries that comfortably fit a modal.
    let show = 14usize;
    let skip = count.saturating_sub(show);
    if skip > 0 {
        body += &format!("(showing last {show} of {count})\n");
    }
    body += &format!(
        "{:>6}  {:>9}  {:<16} {:>3}  detail\n",
        "seq", "uptime", "event", "aux"
    );
    for off in (skip * AUDIT_ENTRY_LEN..entries.len()).step_by(AUDIT_ENTRY_LEN) {
        let e = &entries[off..off + AUDIT_ENTRY_LEN];
        let seq = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let t_ms = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        body += &format!(
            "{seq:>6}  {:>8.1}s  {:<16} {:>3}  {}\n",
            t_ms as f64 / 1000.0,
            event_name(e[8]),
            e[9],
            hex(&e[10..18]),
        );
    }
    Ok(("audit journal".into(), body))
}

fn fold(epoch: &[u8], entries: &[u8]) -> Vec<u8> {
    let mut h = epoch.to_vec();
    for off in (0..entries.len()).step_by(AUDIT_ENTRY_LEN) {
        let end = (off + AUDIT_ENTRY_LEN).min(entries.len());
        let mut hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&entries[off..end]);
        h = hasher.finalize().to_vec();
    }
    h
}

/// Challenge-response identity proof (vendor AUDIT_CHECKPOINT): the device signs
/// a fresh challenge with its DEVK-derived P-256 attestation key. We verify the
/// ECDSA signature locally — a genuine cryptographic check, not a display of
/// device-asserted bytes. Touch-gated; PIN if one is set.
pub fn verify_identity(pin: Option<&str>) -> Result<(String, String), String> {
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;

    let mut challenge = [0u8; 16];
    OsRng.fill_bytes(&mut challenge);
    let subpara = Value::Map(vec![(iv(1), Value::Bytes(challenge.to_vec()))]);
    let raw_subpara = cbor(&subpara);
    let mut req = vec![
        (iv(1), iv(VENDOR_AUDIT_CHECKPOINT as i64)),
        (iv(2), subpara),
    ];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_AUDIT_CHECKPOINT, &raw_subpara) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, v) = vendor(&dev, cid, Value::Map(req), 30000);
    match st {
        0 => {}
        0x36 => return Err("device requires a PIN (set one and retry)".into()),
        0x30 => {
            return Err(
                "no OTP DEVK provisioned — attestation unavailable (docs/production.md)".into(),
            );
        }
        0x27 => {
            return Err(
                "no touch within the timeout — press the button when the LED blinks".into(),
            );
        }
        s => return Err(format!("checkpoint failed: {s:#x}")),
    }
    let v = v.ok_or("decode failed")?;
    let head = match map_get(&v, 1) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no head".into()),
    };
    let seq = map_get(&v, 2).and_then(as_u32).ok_or("no seq")?;
    let sig = match map_get(&v, 3) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no signature".into()),
    };
    let pubkey = match map_get(&v, 4) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no pubkey".into()),
    };

    let vk = VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| "bad attestation pubkey")?;
    let signature = Signature::from_der(&sig).map_err(|_| "bad signature DER")?;
    let mut msg = Vec::with_capacity(CKPT_TAG.len() + head.len() + 4 + challenge.len());
    msg.extend_from_slice(CKPT_TAG);
    msg.extend_from_slice(&head);
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&challenge);
    if vk.verify(&msg, &signature).is_err() {
        return Err("SIGNATURE INVALID — this device cannot prove its identity".into());
    }

    let fp: String = Sha256::digest(&pubkey)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    let body = format!(
        "identity verified ✓  (ECDSA P-256 signature over a fresh challenge)\n\n\
         fingerprint : {fp}\n\
         att key     : {}\n\
         chain head  : {}\n\
         seq         : {seq}\n\n\
         Record the fingerprint; pin future checks with `rsk inventory verify --expect-key`.",
        hex(&pubkey),
        hex(&head),
    );
    Ok(("device identity".into(), body))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ===========================================================================
// seed backup (native: MSE + clientPIN proto-2 + BIP-39)
// ===========================================================================

fn client_pin(dev: &hidapi::HidDevice, cid: [u8; 4], fields: Value) -> Option<Value> {
    let mut p = vec![0x06];
    p.extend_from_slice(&cbor(&fields));
    let r = send_cbor(dev, cid, &p, 5000);
    if r.first() != Some(&0) {
        return None;
    }
    ciborium::de::from_reader(&r[1..]).ok()
}

/// clientPIN protocol-two pinUvAuthToken with the acfg permission.
fn acfg_token(dev: &hidapi::HidDevice, cid: [u8; 4], pin: &str) -> Result<[u8; 32], String> {
    let ka = client_pin(dev, cid, Value::Map(vec![(iv(1), iv(2)), (iv(2), iv(2))]))
        .ok_or("getKeyAgreement failed")?;
    let auth = map_get(&ka, 1).ok_or("no keyAgreement")?;
    let (ax, ay) = (coord(auth, -2)?, coord(auth, -3)?);
    let (sk, px, py) = ecdh_pub();
    let z = ecdh_raw(&sk, &ax, &ay).ok_or("ECDH failed")?;
    let aes = hkdf32(&[0u8; 32], &z, b"CTAP2 AES key");
    let mut ph = Sha256::digest(pin.as_bytes())[..16].to_vec();
    let enc = aes_cbc_encrypt(&aes, &ph);
    ph.zeroize();
    let req = Value::Map(vec![
        (iv(1), iv(2)),
        (iv(2), iv(9)),
        (iv(3), cose_key(&px, &py)),
        (iv(6), Value::Bytes(enc)),
        (iv(9), iv(PERM_ACFG)),
    ]);
    let resp = client_pin(dev, cid, req).ok_or("getPinUvAuthToken failed (wrong PIN?)")?;
    let enc_tok = match map_get(&resp, 2) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no token in response".into()),
    };
    let tok = aes_cbc_decrypt(&aes, &enc_tok).ok_or("token decrypt failed")?;
    tok.as_slice()
        .try_into()
        .map_err(|_| "bad token length".into())
}

fn coord(cose: &Value, key: i128) -> Result<[u8; 32], String> {
    match map_get(cose, key) {
        Some(Value::Bytes(b)) if b.len() <= 32 => {
            let mut out = [0u8; 32];
            out[32 - b.len()..].copy_from_slice(b);
            Ok(out)
        }
        _ => Err("missing COSE coordinate".into()),
    }
}

/// MSE key agreement; returns (channel key, AAD = device pubkey).
fn mse(dev: &hidapi::HidDevice, cid: [u8; 4]) -> Result<([u8; 32], [u8; 65]), String> {
    let (sk, px, py) = ecdh_pub();
    let req = Value::Map(vec![
        (iv(1), iv(1)),
        (iv(2), Value::Map(vec![(iv(1), cose_key(&px, &py))])),
    ]);
    let (st, v) = vendor(dev, cid, req, 5000);
    if st != 0 {
        return Err(format!("MSE failed: {st:#x}"));
    }
    let v = v.ok_or("MSE decode")?;
    let dk = map_get(&v, 1).ok_or("no device key")?;
    let (dx, dy) = (coord(dk, -2)?, coord(dk, -3)?);
    let z = ecdh_raw(&sk, &dx, &dy).ok_or("ECDH failed")?;
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    aad[1..33].copy_from_slice(&dx);
    aad[33..].copy_from_slice(&dy);
    Ok((hkdf32(b"", &z, &aad), aad))
}

fn gate_param(token: Option<&[u8; 32]>, subcmd: u8, raw_subpara: &[u8]) -> Option<(Value, Value)> {
    let token = token?;
    let mut msg = vec![0xffu8; 32];
    msg.extend_from_slice(&[CTAP_VENDOR, subcmd]);
    msg.extend_from_slice(raw_subpara);
    Some((iv(2), Value::Bytes(hmac256(token, &msg))))
}

/// Export the 32-byte seed and return it as a 24-word BIP-39 phrase.
pub fn backup_export(pin: Option<&str>) -> Result<String, String> {
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;
    let (key, aad) = mse(&dev, cid)?;

    let mut req = vec![(iv(1), iv(2))]; // BACKUP_EXPORT
    if let Some((_, v)) = gate_param(token.as_ref(), 2, &[]) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&Value::Map(req)));
    let r = send_cbor(&dev, cid, &payload, 20000);
    match r.first() {
        Some(&0) => {}
        Some(&0x36) => return Err("device requires a PIN (set one and retry)".into()),
        Some(&0x30) => return Err("export refused — already sealed".into()),
        Some(s) => return Err(format!("export failed: {s:#x}")),
        None => return Err("no response (timeout / no touch)".into()),
    }
    let v: Value = ciborium::de::from_reader(&r[1..]).map_err(|_| "decode")?;
    let blob = match map_get(&v, 1) {
        Some(Value::Bytes(b)) if b.len() == 60 => b.clone(),
        _ => return Err("bad export blob".into()),
    };
    let mut seed =
        chacha_decrypt(&key, &blob[..12], &aad, &blob[12..]).ok_or("AEAD decrypt failed")?;
    let mnemonic = bip39::Mnemonic::from_entropy(&seed)
        .map_err(|e| e.to_string())?
        .to_string();
    seed.zeroize();
    Ok(mnemonic)
}

/// Seal the one-time backup export window (vendor BACKUP_FINALIZE, subcmd 4).
/// Touch-gated, no PIN; a factory reset reopens it. Irreversible otherwise.
pub fn backup_finalize() -> Result<String, String> {
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let (st, _) = vendor(&dev, cid, Value::Map(vec![(iv(1), iv(4))]), 20000);
    match st {
        0 => Ok("backup window sealed — a factory reset reopens it".into()),
        0x27 => Err("finalize cancelled — no touch".into()),
        s => Err(format!("finalize failed: {s:#x}")),
    }
}

fn seed_fp(words: &str) -> Result<String, String> {
    let m = bip39::Mnemonic::parse(words).map_err(|e| e.to_string())?;
    let (mut ent, len) = m.to_entropy_array();
    let fp = Sha256::digest(&ent[..len])
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    ent.zeroize();
    Ok(fp)
}

/// Verify the native MSE / clientPIN / BIP-39 paths end-to-end without leaking the
/// seed: export, restore the SAME phrase back (identity-preserving), re-export,
/// and confirm the fingerprint is stable. Needs the no-touch build.
pub fn export_selftest(pin: Option<&str>) -> Result<String, String> {
    let words = backup_export(pin)?;
    let fp1 = seed_fp(&words)?;
    backup_restore(&words, pin)?;
    let fp2 = seed_fp(&backup_export(pin)?)?;
    if fp1 != fp2 {
        return Err(format!("round-trip fp mismatch {fp1} != {fp2}"));
    }
    Ok(format!("export+restore round-trip clean  seed_fp={fp1}"))
}

/// Restore the seed from a 24-word BIP-39 phrase.
pub fn backup_restore(phrase: &str, pin: Option<&str>) -> Result<String, String> {
    let m = bip39::Mnemonic::parse(phrase.trim()).map_err(|e| format!("invalid phrase: {e}"))?;
    let (entropy, len) = m.to_entropy_array();
    if len != 32 {
        return Err("phrase must encode 32 bytes (24 words)".into());
    }
    let mut seed = entropy[..32].to_vec();

    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;
    let (key, aad) = mse(&dev, cid)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&chacha_encrypt(&key, &nonce, &aad, &seed));
    seed.zeroize();

    let subpara = Value::Map(vec![(iv(1), Value::Bytes(blob))]);
    let raw_subpara = cbor(&subpara);
    let mut req = vec![(iv(1), iv(3)), (iv(2), subpara)]; // BACKUP_LOAD
    if let Some((_, v)) = gate_param(token.as_ref(), 3, &raw_subpara) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, _) = vendor(&dev, cid, Value::Map(req), 20000);
    match st {
        0 => Ok("seed restored — FIDO identity matches the backup".into()),
        0x36 => Err("device requires a PIN (set one and retry)".into()),
        s => Err(format!("restore failed: {s:#x}")),
    }
}

// ===========================================================================
// Mock provider — drives the whole UI with no hardware (`--demo`).
// ===========================================================================

/// A simulated RS-Key for `--demo`. Actions visibly mutate the fake state but
/// never pretend to touch hardware: every result is prefixed `[demo]`.
pub struct MockProvider {
    idle_color: usize,
    sealed: bool,
}

impl MockProvider {
    pub fn new() -> Self {
        MockProvider {
            idle_color: 6, // cyan
            sealed: false,
        }
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceProvider for MockProvider {
    fn snapshot(&mut self) -> DeviceSnapshot {
        DeviceSnapshot {
            transport: TransportStatus {
                hid: Link::Present,
                pcsc: Link::Present,
                ccid: Link::Present,
                note: None,
            },
            identity: Identity {
                serial: Some("37bebfdca282523b".into()),
                sdk: Some("3.4".into()),
                firmware: Some("5.7.4".into()),
                bcd_device: Some(0x0759),
                aaguid: Some("9c5e0fd2c2c34c2fa1d6e3b7a0c41122".into()),
                product: Some("RS-Key Security Key (demo)".into()),
            },
            fido: FidoState {
                present: true,
                versions: vec!["U2F_V2".into(), "FIDO_2_0".into(), "FIDO_2_1".into()],
                client_pin: Some(true),
                options: vec![
                    "clientPin".into(),
                    "credMgmt".into(),
                    "pinUvAuthToken".into(),
                    "rk".into(),
                    "up".into(),
                ],
            },
            backup: Some(BackupState {
                sealed: self.sealed,
                has_seed: true,
            }),
            lock: Some(LockState {
                locked: false,
                unlocked: false,
            }),
            secure_boot: Some(SecureBootState {
                enabled: true,
                locked: false,
                bootkey: 1,
            }),
            rollback: Some(RollbackState {
                required: false,
                version: 0,
                capacity: 48,
            }),
            attestation: Some(AttestationState {
                installed: false,
                chain_sha256: None,
            }),
            flash: Some(FlashState {
                free: 1_048_576,
                used: 4_096,
                kv_total: 65_536,
                files: 7,
                chip: 8_388_608,
            }),
            applets: Applets {
                openpgp: Some(true),
                piv: Some(true),
                oath: Some(true),
                otp: Some(true),
            },
            errors: Vec::new(),
            demo: true,
        }
    }

    fn run(&mut self, action: Action, _input: &ActionInput) -> ActionResult {
        match action {
            Action::Refresh => ActionResult::Ok("status refreshed".into()),
            Action::LedGet => ActionResult::Report {
                title: "LED state".into(),
                body: format!(
                    "mode = steady\nidle        {}  (brightness 16) effect=vapor\nprocessing  blue  (brightness 32) effect=flow\ntouch       green  (brightness 64) effect=bounce\nboot        white  (brightness  8) effect=sparkle\n",
                    COLORS[self.idle_color]
                ),
            },
            Action::LedCycle => {
                self.idle_color = (self.idle_color % 7) + 1;
                ActionResult::Ok(format!("[demo] idle color → {}", COLORS[self.idle_color]))
            }
            Action::RebootApp => ActionResult::Ok("[demo] reboot → app (no device touched)".into()),
            Action::RebootBootsel => {
                ActionResult::Ok("[demo] reboot → BOOTSEL (no device touched)".into())
            }
            Action::BackupExport => {
                // A canonical, obviously-fake mnemonic (entropy = 32 zero bytes).
                let words = bip39::Mnemonic::from_entropy(&[0u8; 32])
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                ActionResult::Reveal {
                    title: "seed · BIP-39 (DEMO — not a real key)".into(),
                    body: Zeroizing::new(words),
                }
            }
            Action::BackupRestore => ActionResult::Ok("[demo] seed restored".into()),
            Action::BackupFinalize => {
                self.sealed = true;
                ActionResult::Ok("[demo] backup window sealed".into())
            }
            Action::AuditRead => ActionResult::Report {
                title: "audit journal".into(),
                body: "window [0, 4)  —  4 entries, 0 folded into the epoch\n\
                       epoch : 00000000…  head : 7f3a91c4…  (chain over the window)\n\n\
                          seq     uptime  event            aux  detail\n\
                           0       0.4s  BOOT                0  0000000000000000\n\
                           1       2.1s  PIN_SET             0  0000000000000000\n\
                           2      14.8s  MAKE_CREDENTIAL     1  a1b2c3d4e5f60718\n\
                           3      31.0s  GET_ASSERTION       1  a1b2c3d4e5f60718\n"
                    .into(),
            },
            Action::Verify => ActionResult::Report {
                title: "device identity".into(),
                body: "identity verified ✓  (demo — no real signature)\n\n\
                       fingerprint : demo0000demo0000\n\
                       att key     : 04demo…\n\
                       seq         : 4\n"
                    .into(),
            },
        }
    }
}
