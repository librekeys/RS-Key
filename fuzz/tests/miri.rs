// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

// =========================================================================
// Miri integration tests — exercises each fuzz target's logic under the
// Rust Miri interpreter to detect undefined behaviour. Each test mirrors a
// fuzz target from fuzz_targets/ using fixed representative inputs.
//
// Run with:
//   MIRIFLAGS="-Zmiri-many-seeds -Zdeduplicate-diagnostics \
//              -Zmiri-strict-provenance" \
//     cargo +nightly miri test --manifest-path fuzz/Cargo.toml
//
// Or (with Nix):
//   MIRIFLAGS="..." nix develop .#fuzz -c cargo miri test
//
// Filter to a single target: add `-- miri_apdu`
// =========================================================================

use rsk_crypto::{base64url, chachapoly, sha256, Device, HmacDrbg, MlKem768Pair};
use rsk_crypto::{kdf::PinKdf, pinproto, mldsa44_verify, mlkem768_encapsulate};
use rsk_fido::credential::{credential_create, credential_load, CredExt, CredInput};
use rsk_fido::hmacsecret;
use rsk_fido::seed::{ensure_seed, load_keydev};
use rsk_fido::{Ctx, FidoState, Rng};
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::Fs;
use rsk_openpgp::consts::{PW1_DEFAULT, PW1_MODE81, PW1_MODE82, PW3_DEFAULT, PW3_MODE83};
use rsk_openpgp::keys::{curve_from_attr, rsa_sign_em, Curve, PrivKey, MAX_RSA_DIGESTINFO};
use rsk_openpgp::pso::parse_ecdh_point;
use rsk_openpgp::{scan_files, OpenpgpApplet};
use rsk_otp::hid::{FrameRx, FrameTx, RxOutcome, REPORT_SIZE};
use rsk_rescue::phy::{PhyData, PHY_MAX_SIZE};
use rsk_sdk::apdu::Apdu;
use rsk_sdk::tlv::{find_tag, Tlv};
use rsk_sdk::{Applet, ResBuf};
use rsk_usb::ctaphid::{Outcome, Reassembler, TxFrames, CTAP_MAX_MESSAGE, HID_RPT_SIZE};
use rsk_usb::ccid::process_message;

use core::cell::RefCell;

// -------------------------------------------------------------------------
// Shared RNG and helpers
// -------------------------------------------------------------------------

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

struct CountRng(u8);
impl rsk_oath::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}
impl rsk_openpgp::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}
impl rsk_rescue::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
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

// =========================================================================
// apdu
// =========================================================================

#[test]
fn miri_apdu() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x00\xa4\x04\x00",
        b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x05\x27\x21\x01\x01",
        b"\xff\xff\xff\xff\xff",
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
    ] {
        let _ = Apdu::parse(data);
    }
}

// =========================================================================
// tlv
// =========================================================================

#[test]
fn miri_tlv() {
    for data in [
        &b""[..],
        b"\x00\x01\xff",
        b"\x30\x04\x02\x01\x01\x02\x01\x02",
        b"\x5a\x02\xaa\xbb",
        b"\x80\x00",
        b"\x1f\xff",
        b"\xff\xff\xff\xff\xff",
    ] {
        for (_tag, _value) in Tlv::new(data) {}
        let _ = find_tag(data, 0x5A);
    }
}

// =========================================================================
// fs_meta
// =========================================================================

#[test]
fn miri_fs_meta() {
    use rsk_fs::{Fs, Storage};
    use rsk_sdk::error::Result;

    struct MetaBlob<'a>(&'a [u8]);
    impl Storage for MetaBlob<'_> {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if fid != rsk_fs::EF_META {
                return None;
            }
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            Some(self.0.len())
        }
        fn write(&mut self, _fid: u16, _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn remove(&mut self, _fid: u16) -> Result<()> {
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            (fid == rsk_fs::EF_META).then_some(self.0.len())
        }
        fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) {}
    }
    static TABLE: &[rsk_fs::FileDesc] = &[];

    for data in [&b""[..], b"\x00\x00", b"\xcf\x01\x01\x42"] {
        let mut fs = Fs::new(MetaBlob(data), TABLE);
        let mut out = [0u8; 256];
        for fid in [0x0000, 0xCF01, 0xE010, 0xFFFF] {
            let _ = fs.meta_find(fid, &mut out);
        }
    }
}

// =========================================================================
// ctaphid
// =========================================================================

#[test]
fn miri_ctaphid() {
    for data in [
        &b""[..],
        &[0x12; 64],
        &[0x12; 128],
        &[0x12; 200],
        &[
            0x00, 0x01, 0x02, 0x03, 0x81, 0x00, 0x07, 0x08, // init
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, // cont
            0x00, 0x07, 0x00, 0x07, 0x00, 0x07, // seq 1
            0x00, 0x07, 0x00, 0x07, 0x00, 0x07, // seq 2
        ][..],
    ] {
        let mut asm = Reassembler::new();
        for chunk in data.chunks(HID_RPT_SIZE) {
            let mut frame = [0u8; HID_RPT_SIZE];
            frame[..chunk.len()].copy_from_slice(chunk);
            if let Outcome::Message(_cid, _cmd) = asm.feed(&frame) {
                assert!(asm.message().len() <= CTAP_MAX_MESSAGE);
            }
        }
    }
}

// =========================================================================
// ctaphid_roundtrip
// =========================================================================

#[test]
fn miri_ctaphid_roundtrip() {
    const CID: u32 = 0x0100_0000;
    const CMD: u8 = 0x80 | 0x01;
    for data in [&b""[..], b"\x00", b"\x01\x02\x03", &[0x55; 256], &[0x55; 1000]] {
        if data.len() > CTAP_MAX_MESSAGE {
            continue;
        }
        let mut asm = Reassembler::new();
        let mut last = Outcome::None;
        for frame in TxFrames::new(CID, CMD, data) {
            last = asm.feed(&frame);
        }
        match last {
            Outcome::Message(cid, cmd) => {
                assert_eq!(cid, CID);
                assert_eq!(cmd, CMD);
                assert_eq!(asm.message(), data);
            }
            other => panic!("framed message did not reassemble: {other:?}"),
        }
    }
}

// =========================================================================
// base64url
// =========================================================================

#[test]
fn miri_base64url() {
    for data in [&b""[..], b"hello", b"aGVsbG8", &[0xFF; 64], &[0x41; 128]] {
        let mut dbuf = [0u8; 8192];
        let _ = base64url::decode(&mut dbuf, data);

        let src = &data[..data.len().min(1024)];
        let mut ebuf = [0u8; 1400];
        let en = base64url::encode(&mut ebuf, src).expect("dst large enough");
        let mut back = [0u8; 1024];
        let dn = base64url::decode(&mut back, &ebuf[..en]).expect("self-encoded is valid");
        assert_eq!(&back[..dn], src);
    }
}

// =========================================================================
// aes_gcm
// =========================================================================

#[test]
fn miri_aes_gcm() {
    for data in [&[0u8; 64], &[1u8; 64]] {
        if data.len() < 44 {
            continue;
        }
        let key: [u8; 32] = data[..32].try_into().unwrap();
        let nonce: [u8; 12] = data[32..44].try_into().unwrap();
        let msg = &data[44..];
        let n = msg.len().min(64);
        let aad_len = msg.len().min(16);

        let mut buf = [0u8; 128];
        buf[..n].copy_from_slice(&msg[..n]);
        let mut aad = [0u8; 16];
        aad[..aad_len].copy_from_slice(&msg[..aad_len]);
        let aad = &aad[..aad_len];

        let tag = rsk_crypto::aes::aes256gcm_encrypt(&key, &nonce, aad, &mut buf[..n]);
        let mut dec = [0u8; 128];
        dec[..n].copy_from_slice(&buf[..n]);
        rsk_crypto::aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
            .expect("round-trip authenticates");
        assert_eq!(&dec[..n], &msg[..n]);

        let mut bad = tag;
        bad[0] ^= 0xff;
        let mut dec2 = [0u8; 128];
        dec2[..n].copy_from_slice(&buf[..n]);
        assert!(rsk_crypto::aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err());
    }
}

// =========================================================================
// chachapoly
// =========================================================================

#[test]
fn miri_chachapoly() {
    for data in [&[0u8; 64], &[2u8; 64]] {
        if data.len() < 44 {
            continue;
        }
        let key: [u8; 32] = data[..32].try_into().unwrap();
        let nonce: [u8; 12] = data[32..44].try_into().unwrap();
        let msg = &data[44..];
        let n = msg.len().min(64);
        let aad_len = msg.len().min(16);

        let mut buf = [0u8; 128];
        buf[..n].copy_from_slice(&msg[..n]);
        let mut aad = [0u8; 16];
        aad[..aad_len].copy_from_slice(&msg[..aad_len]);
        let aad = &aad[..aad_len];

        let tag = chachapoly::chacha20poly1305_encrypt(&key, &nonce, aad, &mut buf[..n]);
        let mut dec = [0u8; 128];
        dec[..n].copy_from_slice(&buf[..n]);
        chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
            .expect("round-trip authenticates");
        assert_eq!(&dec[..n], &msg[..n]);

        let mut bad = tag;
        bad[0] ^= 0xff;
        let mut dec2 = [0u8; 128];
        dec2[..n].copy_from_slice(&buf[..n]);
        assert!(
            chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err()
        );
    }
}

// =========================================================================
// fido_cbor
// =========================================================================

#[test]
fn miri_fido_cbor() {
    for data in [
        &b"\x04\xa1\x01\xa5"[..], // getInfo
        &b"\xff"[..],
        b"\x01",
        &[],
    ] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut out = [0u8; 2048];
        let mut state = FidoState::new();
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let n = rsk_fido::process_cbor(&mut ctx, data, &mut out);
        assert!(n >= 1 && n <= out.len());
    }
}

// =========================================================================
// fido_vendor
// =========================================================================

#[test]
fn miri_fido_vendor() {
    use rsk_fido::seed::seal_seed_locked;
    use rsk_fido::vendor::vendor;

    for (data, soft_lock) in [(&b"\x00"[..], false), (b"\x01", true)] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        if soft_lock {
            let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
            let _ = fs.put(rsk_fido::consts::EF_KEY_DEV_ENC, &blob);
            let _ = fs.delete(rsk_fido::consts::EF_KEY_DEV);
        }
        let mut state = FidoState::new();
        state.mse_active = true;
        state.mse_key = [0x5A; 32];
        state.mse_pub = [0x04; 65];
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let n = vendor(&mut ctx, data, &mut out);
        if let Ok(len) = n {
            assert!(len <= out.len());
        }
    }
}

// =========================================================================
// fido_cred
// =========================================================================

#[test]
fn miri_fido_cred() {
    for data in [&b""[..], b"\x00", b"\x00\x01\x02", &[0xFF; 128]] {
        let seed = [0x42u8; 32];
        let rp_hash = [0x99u8; 32];
        let mut scratch = [0u8; 2048];
        assert!(credential_load(&seed, data, &rp_hash, &mut scratch).is_none());
    }
}

// =========================================================================
// fido_cred_ext
// =========================================================================

#[test]
fn miri_fido_cred_ext() {
    use rsk_fido::consts::MAX_CREDBLOB_LENGTH;
    for (flags, blob) in [(0u8, &b""[..]), (3, b"myblob"), (0x10, b""), (0xFF, b"x")] {
        let d = dev();
        let seed = [0x42u8; 32];
        let rp_hash = sha256(b"example.com");
        let iv = [0x11u8; 12];
        let ext = CredExt {
            cred_protect: (flags & 0x03) as u64,
            cred_blob: blob,
            hmac_secret: flags & 0x10 != 0,
            large_blob_key: flags & 0x20 != 0,
            third_party_payment: flags & 0x40 != 0,
        };
        let input = CredInput {
            rp_id: "example.com",
            user_id: &[1, 2, 3, 4],
            user_name: "u",
            user_display_name: "d",
            use_sign_count: true,
            rk: false,
            created_ms: 0,
            alg: -7,
            curve: 1,
            ext,
        };
        let mut out = [0u8; 1024];
        if let Ok(len) = credential_create(&seed, &d, &input, &rp_hash, &iv, &mut out) {
            let mut scratch = [0u8; 1024];
            let c = credential_load(&seed, &out[..len], &rp_hash, &mut scratch)
                .expect("a freshly sealed box must load");
            assert_eq!(c.ext.cred_protect, (flags & 0x03) as u64);
            assert_eq!(c.ext.hmac_secret, flags & 0x10 != 0);
            assert_eq!(c.ext.large_blob_key, flags & 0x20 != 0);
            assert_eq!(c.ext.third_party_payment, flags & 0x40 != 0);
            if !blob.is_empty() && blob.len() < MAX_CREDBLOB_LENGTH {
                assert_eq!(c.ext.cred_blob, blob);
            } else {
                assert!(c.ext.cred_blob.is_empty());
            }
        }
    }
}

// =========================================================================
// fido_hmac_secret
// =========================================================================

#[test]
fn miri_fido_hmac_secret() {
    for data in [&b""[..], b"\x00", b"\xa1\x02\x58\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"] {
        if let Ok(req) = hmacsecret::parse_bytes(data) {
            let mut rng = SeqRng(1);
            let ephemeral = [0x11u8; 32];
            let seed = [0x42u8; 32];
            let cred_id = [0x55u8; 80];
            let mut out = [0u8; 80];
            let _ = hmacsecret::eval(&req, &ephemeral, &seed, &cred_id, false, &mut rng, &mut out);
        }
    }
}

// =========================================================================
// fido_credmgmt
// =========================================================================

#[test]
fn miri_fido_credmgmt() {
    use rsk_fido::credential::credential_store;
    use rsk_fido::credmgmt::cred_mgmt;
    use rsk_fido::state::PERM_CM;

    for data in [&b""[..], b"\x08\xa1\x02\xa1", b"\x05\xa1\x03\xa1\x05\xa1"] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let rp_hash = sha256(b"a.co");
        if let Some(seed) = load_keydev(&d, &mut fs) {
            let input = CredInput {
                rp_id: "a.co",
                user_id: &[1, 2],
                user_name: "u",
                user_display_name: "",
                use_sign_count: true,
                rk: true,
                created_ms: 1,
                alg: -7,
                curve: 1,
                ext: CredExt {
                    cred_protect: 0,
                    cred_blob: &[],
                    hmac_secret: false,
                    large_blob_key: false,
                    third_party_payment: false,
                },
            };
            let mut cred_box = [0u8; 512];
            if let Ok(len) =
                credential_create(&seed, &d, &input, &rp_hash, &[0x11; 12], &mut cred_box)
            {
                let _ = credential_store(
                    &seed, &d, &mut fs, &cred_box[..len], &rp_hash, "a.co", &[1, 2],
                );
            }
        }
        let mut state = FidoState::new();
        state.paut.token = [0x99; 32];
        state.paut.permissions = PERM_CM;
        state.begin_using_token(false);
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 2,
        };
        if let Ok(n) = cred_mgmt(&mut ctx, data, &mut out) {
            assert!(n <= out.len());
        }
    }
}

// =========================================================================
// fido_u2f
// =========================================================================

#[test]
fn miri_fido_u2f() {
    for data in [
        &b"\x00\x03\x00\x00\x00\x00\x00"[..], // version
        b"\x00\x01\x00\x00\x00\x40\x00\x00",  // register-like
    ] {
        let Ok(apdu) = Apdu::parse(data) else { continue };
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut out = [0u8; 2048];
        let mut state = FidoState::new();
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let (_sw, n) = rsk_fido::u2f::process_u2f(&mut ctx, &apdu, &mut out);
        assert!(n <= out.len());
    }
}

// =========================================================================
// fido_largeblobs
// =========================================================================

#[test]
fn miri_fido_largeblobs() {
    use rsk_fido::largeblobs::large_blobs;
    use rsk_fido::state::PERM_LBW;

    for data in [&b""[..], b"\x01", b"\x00"] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut state = FidoState::new();
        state.paut.token = [0x99; 32];
        state.paut.permissions = PERM_LBW;
        state.begin_using_token(false);
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 2,
        };
        if let Ok(n) = large_blobs(&mut ctx, data, &mut out) {
            assert!(n <= out.len());
        }
    }
}

// =========================================================================
// pin_kdf
// =========================================================================

#[test]
fn miri_pin_kdf() {
    for data in [&b""[..], b"short", b"123456", &[0xFF; 64]] {
        let d = dev();
        let _ = d.hash_multi(data);
        let _ = d.double_hash_pin(data);
        let _ = d.derive_kver(data);
        let _ = d.pin_derive_verifier(data);
        let _ = d.pin_derive_session(data);

        let token = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let pt = &data[..data.len().min(32)];
        let mut out = [0u8; 12 + 32 + 16];
        if let Ok(n) = d.encrypt_with_aad(&token, pt, PinKdf::V2, &nonce, &mut out) {
            let mut back = [0u8; 32];
            let m = d
                .decrypt_with_aad(&token, &out[..n], PinKdf::V2, &mut back)
                .expect("round-trip authenticates");
            assert_eq!(&back[..m], pt);
        }
    }
}

// =========================================================================
// pinproto
// =========================================================================

#[test]
fn miri_pinproto() {
    use rsk_crypto::pinproto::PinProto;

    let shared = [0x5Au8; 64];
    for proto in [PinProto::One, PinProto::Two] {
        let scalar = [0x11u8; 32];
        let mut out = [0u8; 64];
        let _ = pinproto::ecdh(proto, &scalar, &[0x5A; 32], &[0xA5; 32], &mut out);

        for ct in [&b""[..], &[0u8; 32], &[0u8; 64]] {
            let mut pt = [0u8; 256];
            let _ = pinproto::decrypt(proto, &shared, ct, &mut pt);
        }

        let data = [0x42u8; 16];
        let iv = [0x77u8; 16];
        let mut ct = [0u8; 32 + 16];
        if let Ok(n) = pinproto::encrypt(proto, &shared, &iv, &data, &mut ct) {
            let mut back = [0u8; 32];
            let m = pinproto::decrypt(proto, &shared, &ct[..n], &mut back).expect("round-trip");
            assert_eq!(&back[..m], &data);
        }

        let _ = pinproto::verify(proto, &shared, &data, &data);
    }
}

// =========================================================================
// openpgp_apdu
// =========================================================================

#[test]
fn miri_openpgp_apdu() {
    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    fn run(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let d = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    if scan_files(&d, &mut fs, &mut CountRng(0)).is_err() {
        return;
    }
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    for (mode, pin) in [
        (PW3_MODE83, PW3_DEFAULT),
        (PW1_MODE81, PW1_DEFAULT),
        (PW1_MODE82, PW1_DEFAULT),
    ] {
        let mut v = vec![0x00, rsk_openpgp::consts::INS_VERIFY, 0x00, mode, pin.len() as u8];
        v.extend_from_slice(pin);
        run(&mut app, &mut fs, &v);
    }

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xca\x00\x00",
        b"\x00\xc0\x00\x00",
        &[
            0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        ],
    ] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// openpgp_import
// =========================================================================

#[test]
fn miri_openpgp_import() {
    use rsk_openpgp::importdata::{parse_ehl_body, parse_ehl_head};
    for data in [
        &b""[..],
        b"\x00\x00\x00\x00\x00\x00\x00",
        b"\x4d\x00\x7f\x48\x00\x00\x00",
        b"\x00\x00\x7f\x48\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if let Ok((_fid, pos)) = parse_ehl_head(data) {
            let _ = parse_ehl_body(data, pos);
        }
    }
}

// =========================================================================
// openpgp_ecdh
// =========================================================================

#[test]
fn miri_openpgp_ecdh() {
    let p256 = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
    let x25519 = PrivKey::from_scalar(Curve::X25519, &[0x22; 32]).unwrap();
    let mut out = [0u8; 64];

    for data in [
        &b""[..],
        b"\x00",
        &[0x04u8; 65],
        b"\xa6\x0e\x7f\x49\x0c\x86\x0a\x41\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if let Some(point) = parse_ecdh_point(data) {
            let _ = p256.ecdh(point, &mut out);
            let _ = x25519.ecdh(point, &mut out);
        }
        let _ = p256.ecdh(data, &mut out);
        let _ = x25519.ecdh(data, &mut out);
    }
}

// =========================================================================
// openpgp_ec_key
// =========================================================================

#[test]
fn miri_openpgp_ec_key() {
    const CURVES: [Curve; 5] = [Curve::P256, Curve::P384, Curve::P521, Curve::K256, Curve::Ed25519];

    for data in [
        &b"\x00"[..],
        b"\x00\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        b"\x00\x05\x2b\x81\x04\x00\x22",
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if data.is_empty() {
            continue;
        }
        let _ = curve_from_attr(data);
        let curve = CURVES[data[0] as usize % CURVES.len()];
        if let Some(key) = PrivKey::from_scalar(curve, &data[1..]) {
            let mut pt = [0u8; 200];
            let _ = key.public_point(&mut pt);
        }
    }
}

// =========================================================================
// openpgp_rsa_sign
// =========================================================================

#[test]
fn miri_openpgp_rsa_sign() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x00\x00\x00\x00\x00\x00",
    ] {
        let mut em = [0u8; MAX_RSA_DIGESTINFO];
        if let Some(n) = rsa_sign_em(data, &mut em) {
            assert!(n <= MAX_RSA_DIGESTINFO);
        }
    }
}

// =========================================================================
// ccid
// =========================================================================

#[test]
fn miri_ccid() {
    const ATR: &[u8] = &[0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03];
    for data in [
        &b""[..],
        b"\x62\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x6f\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        &[
            0x6f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00,
            0x00,
        ],
    ] {
        let mut status = 0u8;
        let mut out = [0u8; 2048];
        let _ = process_message(data, ATR, &mut status, &mut out);
    }
}

// =========================================================================
// drbg
// =========================================================================

#[test]
fn miri_drbg() {
    for (seed, len) in [
        (&b""[..], 0usize),
        (b"\x01\x02\x03\x04\x05\x06\x07\x08", 32),
        (b"\xff" , 16),
        (&[0xAA; 64], 255),
    ] {
        let mut a = HmacDrbg::new(seed);
        let mut b = HmacDrbg::new(seed);
        let mut out_a = [0u8; 256];
        let mut out_b = [0u8; 256];
        a.fill(&mut out_a[..len]);
        b.fill(&mut out_b[..len]);
        assert_eq!(out_a[..len], out_b[..len]);

        a.reseed(seed);
        let mut more = [0u8; 64];
        a.fill(&mut more);
    }
}

// =========================================================================
// pqc
// =========================================================================

#[test]
fn miri_pqc() {
    use rsk_crypto::mldsa::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN};
    use rsk_crypto::mlkem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM768_SEED_LEN};

    for data in [&[0u8; 16], &[0x42u8; 16]] {
        let mut pk = [0u8; MLDSA44_PK_LEN];
        let mut sig = [0u8; MLDSA44_SIG_LEN];
        let mut ek = [0u8; MLKEM768_EK_LEN];
        let mut ct = [0u8; MLKEM768_CT_LEN];

        for (dst, chunk) in [
            (&mut pk[..], 0),
            (&mut sig[..], 1),
            (&mut ek[..], 2),
            (&mut ct[..], 3),
        ] {
            for (i, b) in dst.iter_mut().enumerate() {
                *b = data.get((i + chunk) % data.len().max(1)).copied().unwrap_or(chunk as u8);
            }
        }

        let _ = mldsa44_verify(&pk, data, &sig);
        let _ = mlkem768_encapsulate(&ek, &[0u8; 32]);

        let mut seed = [0u8; MLKEM768_SEED_LEN];
        let n = data.len().min(MLKEM768_SEED_LEN);
        seed[..n].copy_from_slice(&data[..n]);
        let pair = MlKem768Pair::from_seed(&seed);
        let _ = pair.decapsulate(&ct);
    }
}

// =========================================================================
// mgmt_apdu
// =========================================================================

#[test]
fn miri_mgmt_apdu() {
    use rsk_mgmt::ManagementApplet;
    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x00\x00",
        b"\x00\xcc\x00\x00\x04\x01\x02\x03\x04",
        b"\x00\xcb\x00\x00",
    ] {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4]);
        if let Ok(apdu) = Apdu::parse(data) {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
}

// =========================================================================
// oath_apdu
// =========================================================================

#[test]
fn miri_oath_apdu() {
    use rsk_oath::OathApplet;

    fn run(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 4096];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let touch = RefCell::new(rsk_oath::AlwaysConfirm);
    let mut app =
        OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &touch);

    // Seed one TOTP credential.
    run(&mut app, &mut fs, &[
        0x00, 0x01, 0, 0, 0x1E, 0x71, 0x04, b't', b'o', b't', b'p', 0x73, 0x16, 0x21, 6,
        b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4',
        b'5', b'6', b'7', b'8', b'9', b'0',
    ]);

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xa1\x00\x00",
        b"\x00\x02\x00\x00\x0a\x71\x04totp",
        b"\x00\xa2\x00\x00\x0a\x71\x04totp\x02",
    ] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// otp_apdu
// =========================================================================

#[test]
fn miri_otp_apdu() {
    use rsk_otp::{AlwaysConfirm, OtpApplet};

    fn crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;
        for &b in data {
            crc ^= b as u16;
            for _ in 0..8 {
                let lsb = crc & 1;
                crc >>= 1;
                if lsb == 1 {
                    crc ^= 0x8408;
                }
            }
        }
        crc
    }

    fn run(app: &mut OtpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 1024];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OtpApplet::new([1, 2, 3, 4, 5, 6, 7, 8], &presence);

    let mut cfg = [0u8; 52];
    cfg[22..38].copy_from_slice(&[0xAB; 16]);
    cfg[46] = 0x40;
    cfg[47] = 0x26;
    let crc = !crc16(&cfg[..50]);
    cfg[50..].copy_from_slice(&crc.to_le_bytes());
    let mut put = vec![0x00, 0x01, 0x01, 0x00, 58];
    put.extend_from_slice(&cfg);
    put.extend_from_slice(&[0; 6]);
    run(&mut app, &mut fs, &put);

    for data in [&b"\x00\xa4\x04\x00"[..], b"\x00\xa2\x02\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// otp_hid
// =========================================================================

#[test]
fn miri_otp_hid() {
    for data in [
        &b""[..],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        &[0x12; 32],
        &[0x12; 64],
        &[0xFF; 16],
    ] {
        let mut rx = FrameRx::new();
        let mut tx = FrameTx::new();
        for chunk in data.chunks(REPORT_SIZE) {
            let mut report = [0u8; REPORT_SIZE];
            report[..chunk.len()].copy_from_slice(chunk);
            match rx.feed(&report) {
                RxOutcome::Frame { slot: _, payload } => {
                    tx.load(&payload);
                    let mut out = [0u8; REPORT_SIZE];
                    let mut guard = 0;
                    while tx.next(&mut out) {
                        guard += 1;
                        assert!(guard < 64, "FrameTx must terminate");
                    }
                }
                RxOutcome::None | RxOutcome::Reset | RxOutcome::BadCrc => {}
            }
        }
    }
}

// =========================================================================
// piv_apdu
// =========================================================================

#[test]
fn miri_piv_apdu() {
    use rsk_piv::{AlwaysConfirm, PivApplet};

    fn run(app: &mut PivApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Vec<u8> {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 4096];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
            return res.as_slice().to_vec();
        }
        Vec::new()
    }

    const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
    const DEFAULT_MGM: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    fn auth_mgm(app: &mut PivApplet, fs: &mut Fs<RamStorage>) {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockDecrypt, KeyInit};
        let wit = run(app, fs, &[0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00]);
        if wit.len() < 20 {
            return;
        }
        let cipher = aes::Aes192::new(GenericArray::from_slice(&DEFAULT_MGM));
        let mut w = [0u8; 16];
        w.copy_from_slice(&wit[4..20]);
        let mut blk = GenericArray::clone_from_slice(&w);
        cipher.decrypt_block(&mut blk);
        let mut msg = vec![0x00, 0x87, 0x0A, 0x9B, 0x24, 0x7C, 0x22, 0x80, 0x10];
        msg.extend_from_slice(&blk);
        msg.push(0x81);
        msg.push(0x10);
        msg.extend_from_slice(&[0xA5; 16]);
        let _ = run(app, fs, &msg);
    }

    let rng = RefCell::new(CountRng(0));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &pres);
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();

    {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        let _ = Applet::select(&mut app, false, &mut fs, &mut res);
    }
    auth_mgm(&mut app, &mut fs);

    let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    verify.extend_from_slice(&DEFAULT_PIN);
    let _ = run(&mut app, &mut fs, &verify);

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x3f\xff\x05\x5c\x03\x5f\xc1\x06",
        b"\x00\xcb\x3f\xff\x05\x5c\x03\x5f\xc1\x09",
    ] {
        let _ = run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// rescue_apdu
// =========================================================================

#[test]
fn miri_rescue_apdu() {
    use rsk_rescue::{Platform, RescueApplet, SecureBootStatus};

    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    struct FakePlatform {
        time: Option<u32>,
    }
    impl Platform for FakePlatform {
        fn secure_boot_status(&self) -> SecureBootStatus {
            SecureBootStatus {
                enabled: false,
                locked: false,
                bootkey: 0xFF,
            }
        }
        fn now(&self) -> Option<u32> {
            self.time
        }
        fn set_time(&mut self, epoch: u32) {
            self.time = Some(epoch);
        }
        fn request_reboot(&mut self, _bootsel: bool) {}
        fn read_page58_lock_raw(&self) -> Option<u32> {
            Some(0)
        }
        fn lock_page58(&mut self) -> bool {
            true
        }
    }

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x00\x00",
        b"\x00\xcc\x00\x00\x04\x01\x02\x03\x04",
        &[0x00; 10],
    ] {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        let rng = RefCell::new(CountRng(0));
        let platform = RefCell::new(FakePlatform { time: None });
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            64 * 1024,
            4 * 1024 * 1024,
        );
        if let Ok(apdu) = Apdu::parse(data) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
}

// =========================================================================
// phy_tlv
// =========================================================================

#[test]
fn miri_phy_tlv() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x01\x01\x02",
        b"\x02\x02\xa5\xa5",
        b"\x03\x01\x00\x04\x01\x01\x05\x04\x00\x00\x00\x00",
    ] {
        let phy = PhyData::parse(data);
        let mut buf = [0u8; PHY_MAX_SIZE];
        let n = phy.serialize(&mut buf).expect("PHY_MAX_SIZE always fits");
        assert_eq!(PhyData::parse(&buf[..n]), phy);
    }
}

// =========================================================================
// seed_blob
// =========================================================================

#[test]
fn miri_seed_blob() {
    use rsk_fido::seed::{load_keydev, migrate_keydev_boot, migrate_keydev_pin};

    const EF_KEY_DEV: u16 = 0xCC00;
    const OTP: [u8; 32] = [0x5A; 32];

    let dev_old = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let dev_new = Device {
        otp_key: Some(&OTP),
        ..dev_old
    };

    for data in [
        &b"\x01"[..],
        b"\x03",
        b"\x11",
        b"\x13",
        &[0x01; 32],
        &[0x03; 48],
    ] {
        if data.is_empty() || data.len() > 64 {
            continue;
        }
        let mut fs = Fs::new(RamStorage::new(), &[]);
        if fs.put(EF_KEY_DEV, data).is_err() {
            continue;
        }
        if matches!(data[0], 0x03 | 0x11 | 0x13) {
            assert_eq!(load_keydev(&dev_old, &mut fs), None);
        }
        if data[0] == 0x13 {
            assert_eq!(load_keydev(&dev_new, &mut fs), None);
        }
        let _ = load_keydev(&dev_old, &mut fs);
        let _ = load_keydev(&dev_new, &mut fs);
        let _ = migrate_keydev_pin(&dev_old, &mut fs, &[0x42; 16]);
        let _ = migrate_keydev_pin(&dev_new, &mut fs, &[0x42; 16]);
        let _ = migrate_keydev_boot(&dev_new, &mut fs);
        let after_one = load_keydev(&dev_new, &mut fs);
        let _ = migrate_keydev_boot(&dev_new, &mut fs);
        assert_eq!(after_one, load_keydev(&dev_new, &mut fs));
    }
}