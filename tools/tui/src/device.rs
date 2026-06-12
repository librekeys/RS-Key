// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Native device I/O for rsk-tui — FIDO CTAPHID over hidapi and the CCID applets
//! over PC/SC. No external processes: the TUI talks to the key directly.
//!
//! The dashboard reads (getInfo, vendor/rescue status) are unauthenticated. The
//! seed backup (export/restore) implements the full MSE channel (P-256 ECDH ->
//! HKDF -> ChaCha20-Poly1305) and, when a PIN is set, the clientPIN protocol-two
//! pinUvAuthToken (ECDH -> HKDF -> AES-CBC + HMAC) + BIP-39 — all in Rust, no
//! `rsk` shell-out. SLIP-39 and the picotool/BOOTSEL fuse rituals stay in the CLI.

use aes::Aes256;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ciborium::value::{Integer, Value};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use pcsc::{Context, Protocols, Scope, ShareMode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const REPORT_LEN: usize = 64;
const CTAPHID_INIT: u8 = 0x86;
const CTAPHID_CBOR: u8 = 0x90;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const CTAP_VENDOR: u8 = 0x41;
const PERM_ACFG: i64 = 0x20;

const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];
const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

pub const COLORS: [&str; 8] = [
    "off", "red", "green", "blue", "yellow", "magenta", "cyan", "white",
];

#[derive(Default)]
pub struct Status {
    pub fido_present: bool,
    pub fw: Option<String>,
    pub versions: Vec<String>,
    pub client_pin: Option<bool>,
    pub aaguid: Option<String>,
    pub backup: Option<(bool, bool)>,
    /// Soft-lock state from the same vendor STATE read: (locked, unlocked).
    pub lock: Option<(bool, bool)>,
    pub secure_boot: Option<(bool, bool, u8)>,
}

// ---- FIDO CTAPHID (hidapi) ----

fn hid_open() -> Option<hidapi::HidDevice> {
    let api = hidapi::HidApi::new().ok()?;
    let info = api
        .device_list()
        .find(|d| d.usage_page() == FIDO_USAGE_PAGE)?;
    info.open_device(&api).ok()
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

// ---- CBOR helpers ----

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

// ---- crypto primitives ----

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

fn read_fido(s: &mut Status) {
    let Some(dev) = hid_open() else { return };
    s.fido_present = true;
    let Some(cid) = ctaphid_init(&dev) else {
        return;
    };
    let gi = send_cbor(&dev, cid, &[0x04], 2000);
    if gi.first() == Some(&0)
        && let Ok(v) = ciborium::de::from_reader::<Value, _>(&gi[1..])
    {
        if let Some(Value::Array(a)) = map_get(&v, 1) {
            s.versions = a
                .iter()
                .filter_map(|x| x.as_text().map(String::from))
                .collect();
        }
        if let Some(Value::Integer(i)) = map_get(&v, 14) {
            let n = i128::from(*i) as u32;
            s.fw = Some(format!(
                "{}.{}.{}",
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            ));
        }
        if let Some(Value::Bytes(b)) = map_get(&v, 3) {
            s.aaguid = Some(b.iter().map(|x| format!("{x:02x}")).collect());
        }
        if let Some(Value::Map(opts)) = map_get(&v, 4) {
            for (k, val) in opts {
                if k.as_text() == Some("clientPin") {
                    s.client_pin = val.as_bool();
                }
            }
        }
    }
    let rb = send_cbor(&dev, cid, &[0x41, 0xA1, 0x01, 0x05], 2000);
    if rb.first() == Some(&0)
        && let Ok(v) = ciborium::de::from_reader::<Value, _>(&rb[1..])
    {
        s.backup = Some((
            map_get(&v, 1).and_then(Value::as_bool).unwrap_or(false),
            map_get(&v, 2).and_then(Value::as_bool).unwrap_or(false),
        ));
        // Keys 3/4 exist from bcdDevice 0x0742 (soft-lock support) on.
        if let (Some(locked), Some(unlocked)) = (
            map_get(&v, 3).and_then(Value::as_bool),
            map_get(&v, 4).and_then(Value::as_bool),
        ) {
            s.lock = Some((locked, unlocked));
        }
    }
}

// ---- CCID applets (PC/SC) ----

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
            .find(|r| r.to_string_lossy().contains("RSK"))
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

    fn select(&mut self, aid: &[u8]) -> Result<(), String> {
        let mut a = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        a.extend_from_slice(aid);
        a.push(0x00);
        let (_, s1, s2) = self.apdu(&a)?;
        if (s1, s2) != (0x90, 0x00) {
            return Err(format!("SELECT failed {s1:02X}{s2:02X}"));
        }
        Ok(())
    }
}

fn read_secure_boot(s: &mut Status) {
    let Ok(mut c) = Ccid::open() else { return };
    if c.select(RESCUE_AID).is_err() {
        return;
    }
    if let Ok((d, 0x90, 0x00)) = c.apdu(&[0x80, 0x1E, 0x03, 0x00, 0x00])
        && d.len() >= 3
    {
        s.secure_boot = Some((d[0] != 0, d[1] != 0, d[2]));
    }
}

pub fn gather() -> Status {
    let mut s = Status::default();
    read_fido(&mut s);
    read_secure_boot(&mut s);
    s
}

// ---- LED / reboot (native, unauthenticated) ----

pub fn led_get() -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let (d, s1, s2) = c.apdu(&[0x00, 0x11, 0x00, 0x00, 0x00])?;
    if (s1, s2) != (0x90, 0x00) || d.len() < 9 {
        return Err(format!("GET LED {s1:02X}{s2:02X}"));
    }
    let names = ["idle", "processing", "touch", "boot"];
    let mut out = format!("mode={}", if d[0] != 0 { "steady" } else { "blink" });
    for (i, name) in names.iter().enumerate() {
        out += &format!(
            "  {name}={}/{}",
            COLORS.get(d[1 + 2 * i] as usize).copied().unwrap_or("?"),
            d[2 + 2 * i]
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
    let next = ((d[1] as usize) % 7) + 1;
    let brightness = if d[2] == 0 { 16 } else { d[2] };
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

// ---- seed backup (native: MSE + clientPIN proto-2 + BIP-39) ----

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
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&req));
    let r = send_cbor(dev, cid, &payload, 5000);
    if r.first() != Some(&0) {
        return Err("MSE failed".into());
    }
    let v: Value = ciborium::de::from_reader(&r[1..]).map_err(|_| "MSE decode")?;
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
    if let Some((k, v)) = gate_param(token.as_ref(), 2, &[]) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
        let _ = k;
    }
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&Value::Map(req)));
    let r = send_cbor(&dev, cid, &payload, 20000);
    match r.first() {
        Some(&0) => {}
        Some(&0x36) => return Err("device requires a PIN".into()),
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
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&Value::Map(vec![(iv(1), iv(4))]))); // BACKUP_FINALIZE
    let r = send_cbor(&dev, cid, &payload, 20000);
    match r.first() {
        Some(&0) => Ok("backup window sealed — a factory reset reopens it".into()),
        Some(&0x27) => Err("finalize cancelled — no touch".into()),
        Some(s) => Err(format!("finalize failed: {s:#x}")),
        None => Err("no response (timeout / no touch)".into()),
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
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&Value::Map(req)));
    let r = send_cbor(&dev, cid, &payload, 20000);
    match r.first() {
        Some(&0) => Ok("seed restored — FIDO identity matches the backup".into()),
        Some(&0x36) => Err("device requires a PIN".into()),
        Some(s) => Err(format!("restore failed: {s:#x}")),
        None => Err("no response (timeout / no touch)".into()),
    }
}
