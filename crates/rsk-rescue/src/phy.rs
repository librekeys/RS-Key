// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `phy` device-configuration blob: a TLV record in `EF_PHY` holding USB
//! identity (VID/PID, product string), LED wiring and options. The rescue applet
//! reads/writes it verbatim; at boot the firmware applies VID/PID and the product string.

use rsk_fs::{Fs, Storage};

/// The phy record file. Outside every applet reset scope — it survives FIDO
/// reset / OpenPGP TERMINATE / PIV reset, like the device key.
pub const EF_PHY: u16 = 0xE020;

// Wire format: one-byte tag, one-byte length. VIDPID = VID ‖ PID big-endian;
// USB_PRODUCT counts a trailing NUL in its length.
const TAG_VIDPID: u8 = 0x0;
const TAG_LED_GPIO: u8 = 0x4;
const TAG_LED_BRIGHTNESS: u8 = 0x5;
const TAG_OPTS: u8 = 0x6;
const TAG_UP_BTN: u8 = 0x8;
const TAG_USB_PRODUCT: u8 = 0x9;
const TAG_ENABLED_CURVES: u8 = 0xA;
const TAG_ENABLED_USB_ITF: u8 = 0xB;
const TAG_LED_DRIVER: u8 = 0xC;

pub const OPT_WCID: u16 = 0x1;
pub const OPT_DIMM: u16 = 0x2;
pub const OPT_DISABLE_POWER_RESET: u16 = 0x4;
pub const OPT_LED_STEADY: u16 = 0x8;

pub const USB_ITF_CCID: u8 = 0x1;
pub const USB_ITF_WCID: u8 = 0x2;
pub const USB_ITF_HID: u8 = 0x4;
pub const USB_ITF_KB: u8 = 0x8;
pub const USB_ITF_LWIP: u8 = 0x10;
pub const USB_ITF_ALL: u8 = USB_ITF_CCID | USB_ITF_WCID | USB_ITF_HID | USB_ITF_KB | USB_ITF_LWIP;

/// The interfaces this firmware can instantiate (WCID/LWIP are not built).
pub const USB_ITF_SUPPORTED: u8 = USB_ITF_CCID | USB_ITF_HID | USB_ITF_KB;

/// The boot-effective interface mask. A stored mask that disables every
/// interface we have would leave the device USB-dead — and with CCID gone the
/// rescue applet that could rewrite the record is unreachable, so the only way
/// back would be a full flash wipe. Such a mask falls back to ALL.
pub fn effective_usb_itf(phy: &PhyData) -> u8 {
    let mask = phy.enabled_usb_itf.unwrap_or(USB_ITF_ALL);
    if mask & USB_ITF_SUPPORTED == 0 {
        USB_ITF_ALL
    } else {
        mask
    }
}

/// Largest serialized record (every TLV present, 32-byte product).
pub const PHY_MAX_SIZE: usize =
    (2 + 4) + (2 + 1) + (2 + 1) + (2 + 2) + (2 + 1) + (2 + 33) + (2 + 4) + (2 + 1) + (2 + 1);

const PRODUCT_CAP: usize = 32;

/// The USB product string: raw bytes as stored on the wire, NUL excluded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Product {
    buf: [u8; PRODUCT_CAP],
    len: u8,
}

impl Product {
    pub fn new(s: &[u8]) -> Option<Self> {
        if s.is_empty() || s.len() > PRODUCT_CAP {
            return None;
        }
        let mut buf = [0u8; PRODUCT_CAP];
        buf[..s.len()].copy_from_slice(s);
        Some(Product {
            buf,
            len: s.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// The parsed phy record; absent TLVs are `None`. `opts` has no presence
/// flag — absent means 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PhyData {
    pub vid_pid: Option<(u16, u16)>,
    pub led_gpio: Option<u8>,
    pub led_brightness: Option<u8>,
    pub opts: u16,
    pub up_btn: Option<u8>,
    pub usb_product: Option<Product>,
    pub enabled_curves: Option<u32>,
    pub enabled_usb_itf: Option<u8>,
    pub led_driver: Option<u8>,
}

impl PhyData {
    /// Unknown tags are skipped; a TLV running past the end of the input ends
    /// the parse — the parser must never overread. A record without
    /// ENABLED_USB_ITF gets ALL.
    pub fn parse(data: &[u8]) -> PhyData {
        let mut phy = PhyData::default();
        let mut p = data;
        while p.len() >= 2 {
            let tag = p[0];
            let tlen = p[1] as usize;
            p = &p[2..];
            if tlen > p.len() {
                break;
            }
            let v = &p[..tlen];
            match (tag, tlen) {
                (TAG_VIDPID, 4) => {
                    let vid = u16::from_be_bytes([v[0], v[1]]);
                    let pid = u16::from_be_bytes([v[2], v[3]]);
                    phy.vid_pid = Some((vid, pid));
                }
                (TAG_LED_GPIO, 1) => phy.led_gpio = Some(v[0]),
                (TAG_LED_BRIGHTNESS, 1) => phy.led_brightness = Some(v[0]),
                (TAG_OPTS, 2) => phy.opts = u16::from_be_bytes([v[0], v[1]]),
                (TAG_UP_BTN, 1) => phy.up_btn = Some(v[0]),
                (TAG_USB_PRODUCT, 1..=33) => {
                    // Length includes a trailing NUL; the string also stops at
                    // an embedded NUL.
                    let s = &v[..v.iter().position(|&b| b == 0).unwrap_or(tlen)];
                    phy.usb_product = Product::new(s);
                }
                (TAG_ENABLED_CURVES, 4) => {
                    phy.enabled_curves = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                }
                (TAG_ENABLED_USB_ITF, 1) => phy.enabled_usb_itf = Some(v[0]),
                (TAG_LED_DRIVER, 1) => phy.led_driver = Some(v[0]),
                _ => {}
            }
            p = &p[tlen..];
        }
        if phy.enabled_usb_itf.is_none() {
            phy.enabled_usb_itf = Some(USB_ITF_ALL);
        }
        phy
    }

    /// Emit a TLV per present field; OPTS always. Returns the length, or `None`
    /// if `out` is too small (`PHY_MAX_SIZE` always fits).
    pub fn serialize(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer { out, len: 0 };
        if let Some((vid, pid)) = self.vid_pid {
            w.tlv(
                TAG_VIDPID,
                &[(vid >> 8) as u8, vid as u8, (pid >> 8) as u8, pid as u8],
            )?;
        }
        if let Some(g) = self.led_gpio {
            w.tlv(TAG_LED_GPIO, &[g])?;
        }
        if let Some(b) = self.led_brightness {
            w.tlv(TAG_LED_BRIGHTNESS, &[b])?;
        }
        w.tlv(TAG_OPTS, &self.opts.to_be_bytes())?;
        if let Some(b) = self.up_btn {
            w.tlv(TAG_UP_BTN, &[b])?;
        }
        if let Some(p) = &self.usb_product {
            let s = p.as_bytes();
            w.raw(&[TAG_USB_PRODUCT, (s.len() + 1) as u8])?;
            w.raw(s)?;
            w.raw(&[0])?;
        }
        if let Some(c) = self.enabled_curves {
            w.tlv(TAG_ENABLED_CURVES, &c.to_be_bytes())?;
        }
        if let Some(i) = self.enabled_usb_itf {
            w.tlv(TAG_ENABLED_USB_ITF, &[i])?;
        }
        if let Some(d) = self.led_driver {
            w.tlv(TAG_LED_DRIVER, &[d])?;
        }
        Some(w.len)
    }
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn raw(&mut self, b: &[u8]) -> Option<()> {
        if self.len + b.len() > self.out.len() {
            return None;
        }
        self.out[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Some(())
    }

    fn tlv(&mut self, tag: u8, v: &[u8]) -> Option<()> {
        self.raw(&[tag, v.len() as u8])?;
        self.raw(v)
    }
}

/// Load the phy record; `None` when none was ever written.
pub fn load<S: Storage>(fs: &mut Fs<S>) -> Option<PhyData> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = fs.read(EF_PHY, &mut buf)?;
    Some(PhyData::parse(&buf[..n]))
}

/// Persist the phy record.
pub fn save<S: Storage>(fs: &mut Fs<S>, phy: &PhyData) -> rsk_sdk::error::Result<()> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy
        .serialize(&mut buf)
        .ok_or(rsk_sdk::error::Error::NoMemory)?;
    fs.put(EF_PHY, &buf[..n])
}

/// Kani proof harnesses (`cargo kani -p rsk-rescue`): the phy record is parsed
/// from flash at every boot and round-trips through the rescue applet's
/// read-modify-write — both directions are small total functions over
/// attacker-/corruption-reachable bytes, so prove them outright (the house
/// rule from docs/testing.md).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `parse` over EVERY byte string up to 12 bytes (past every tag/length
    /// form, with room for several TLVs including a truncated tail): never
    /// panics, never overreads, always terminates, and always materializes an
    /// interface mask — the boot path relies on that.
    #[kani::proof]
    #[kani::unwind(14)]
    fn parse_any_input() {
        const N: usize = 12;
        let data: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let phy = PhyData::parse(&data[..n]);
        assert!(phy.enabled_usb_itf.is_some());
    }

    /// `serialize` then `parse` is the identity on EVERY `PhyData` — every
    /// field-presence combination, every field value, product strings up to 4
    /// bytes (the cap gates only the string copy; the TLV structure is fully
    /// covered) — modulo the one documented normalization: a missing
    /// ENABLED_USB_ITF parses as ALL. The `unwrap` doubles as proof that
    /// `PHY_MAX_SIZE` always fits the record.
    ///
    /// Fields are compared one by one, the product by content: whole-struct
    /// `==` would memcmp `Product`'s full 32-byte buffer and force the unwind
    /// bound (hence every loop's unrolling) from the parser's depth to the
    /// buffer's — ~5× the solve time for a property that is an artifact of
    /// construction, not part of the wire spec.
    #[kani::proof]
    #[kani::unwind(12)]
    fn serialize_parse_roundtrip() {
        const W: usize = 4;
        let mut phy = PhyData::default();
        if kani::any() {
            phy.vid_pid = Some((kani::any(), kani::any()));
        }
        if kani::any() {
            phy.led_gpio = Some(kani::any());
        }
        if kani::any() {
            phy.led_brightness = Some(kani::any());
        }
        phy.opts = kani::any();
        if kani::any() {
            phy.up_btn = Some(kani::any());
        }
        if kani::any() {
            let raw: [u8; W] = kani::any();
            let len: usize = kani::any();
            kani::assume(1 <= len && len <= W);
            // The wire format is NUL-terminated, so a product string cannot
            // contain NUL — parse truncates at the first one.
            for i in 0..len {
                kani::assume(raw[i] != 0);
            }
            phy.usb_product = Product::new(&raw[..len]);
            assert!(phy.usb_product.is_some());
        }
        if kani::any() {
            phy.enabled_curves = Some(kani::any());
        }
        if kani::any() {
            phy.enabled_usb_itf = Some(kani::any());
        }
        if kani::any() {
            phy.led_driver = Some(kani::any());
        }

        let mut buf = [0u8; PHY_MAX_SIZE];
        let n = phy.serialize(&mut buf).unwrap();

        let got = PhyData::parse(&buf[..n]);
        assert_eq!(got.vid_pid, phy.vid_pid);
        assert_eq!(got.led_gpio, phy.led_gpio);
        assert_eq!(got.led_brightness, phy.led_brightness);
        assert_eq!(got.opts, phy.opts);
        assert_eq!(got.up_btn, phy.up_btn);
        match (&got.usb_product, &phy.usb_product) {
            (Some(g), Some(p)) => assert_eq!(g.as_bytes(), p.as_bytes()),
            (None, None) => {}
            _ => panic!("usb_product presence changed across the roundtrip"),
        }
        assert_eq!(got.enabled_curves, phy.enabled_curves);
        assert_eq!(
            got.enabled_usb_itf,
            phy.enabled_usb_itf.or(Some(USB_ITF_ALL))
        );
        assert_eq!(got.led_driver, phy.led_driver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_fields() {
        let phy = PhyData {
            vid_pid: Some((0x1050, 0x0407)),
            led_gpio: Some(16),
            led_brightness: Some(200),
            opts: OPT_LED_STEADY | OPT_DIMM,
            up_btn: Some(1),
            usb_product: Product::new(b"RSK Custom"),
            enabled_curves: Some(0x3FF),
            enabled_usb_itf: Some(USB_ITF_CCID | USB_ITF_HID),
            led_driver: Some(3),
        };
        let mut buf = [0u8; PHY_MAX_SIZE];
        let n = phy.serialize(&mut buf).unwrap();
        assert_eq!(PhyData::parse(&buf[..n]), phy);
    }

    #[test]
    fn vidpid_wire_is_big_endian() {
        let phy = PhyData {
            vid_pid: Some((0x1050, 0x0407)),
            ..Default::default()
        };
        let mut buf = [0u8; PHY_MAX_SIZE];
        let n = phy.serialize(&mut buf).unwrap();
        // VIDPID TLV first: tag 0, len 4, VID be, PID be.
        assert_eq!(
            &buf[..n],
            &[
                0x00, 0x04, 0x10, 0x50, 0x04, 0x07, TAG_OPTS, 0x02, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn parse_defaults_usb_itf_to_all() {
        let phy = PhyData::parse(&[]);
        assert_eq!(phy.enabled_usb_itf, Some(USB_ITF_ALL));
        assert_eq!(phy.vid_pid, None);
        assert_eq!(phy.opts, 0);
    }

    #[test]
    fn effective_usb_itf_applies_mask_but_guards_lockout() {
        let mut phy = PhyData::default();
        // No record / no TLV → ALL.
        assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
        // Any mask keeping at least one supported interface applies verbatim.
        phy.enabled_usb_itf = Some(USB_ITF_CCID | USB_ITF_HID);
        assert_eq!(effective_usb_itf(&phy), USB_ITF_CCID | USB_ITF_HID);
        phy.enabled_usb_itf = Some(USB_ITF_KB);
        assert_eq!(effective_usb_itf(&phy), USB_ITF_KB);
        // A mask with no supported interface (zero, or only WCID/LWIP bits we
        // do not build) would soft-brick USB → falls back to ALL.
        phy.enabled_usb_itf = Some(0);
        assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
        phy.enabled_usb_itf = Some(USB_ITF_WCID | USB_ITF_LWIP);
        assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    }

    #[test]
    fn parse_skips_unknown_tags_and_truncation_is_safe() {
        // Unknown tag 0x7F (3 bytes), then a valid LED_GPIO, then a TLV whose
        // length runs past the input.
        let phy = PhyData::parse(&[0x7F, 3, 1, 2, 3, TAG_LED_GPIO, 1, 9, TAG_OPTS, 2, 0xAA]);
        assert_eq!(phy.led_gpio, Some(9));
        assert_eq!(phy.opts, 0); // truncated OPTS ignored
    }

    #[test]
    fn product_string_stops_at_nul_and_caps_at_32() {
        let phy = PhyData::parse(&[TAG_USB_PRODUCT, 5, b'a', b'b', 0, b'c', 0]);
        assert_eq!(phy.usb_product.unwrap().as_bytes(), b"ab");
        assert!(Product::new(&[b'x'; 33]).is_none());
        assert!(Product::new(b"").is_none());
    }

    #[test]
    fn save_and_load() {
        let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new(), &[]);
        assert!(load(&mut fs).is_none());
        let phy = PhyData {
            led_brightness: Some(50),
            opts: OPT_LED_STEADY,
            ..Default::default()
        };
        save(&mut fs, &phy).unwrap();
        let got = load(&mut fs).unwrap();
        assert_eq!(got.led_brightness, Some(50));
        assert_eq!(got.opts, OPT_LED_STEADY);
        // The load-time default materializes ITF_ALL.
        assert_eq!(got.enabled_usb_itf, Some(USB_ITF_ALL));
    }
}
