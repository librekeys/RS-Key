// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Build script: generates `memory.x` from the flash size, resolves the
//! compile-time USB identity (see [`resolve_identity`]), the XOSC startup-delay
//! multiplier, and the WS2812 LED pin, and bakes them in as `PK_*` env vars /
//! `cfg`s that `main.rs` reads with `env!` / `#[cfg]`.
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// The Waveshare RP2350-One's flash, and the layout the checked-in `memory.x`
/// encodes. A `FLASH_SIZE` equal to this writes that file byte-for-byte.
const DEFAULT_FLASH_SIZE: u32 = 4 * 1024 * 1024;

/// Top-of-flash reserved for the rsk-fs KV store (KVMAIN 1408K + KVCNT 128K);
/// must match `flash_storage.rs` (`MAIN_LEN` + `COUNTER_LEN`). Fixed across
/// flash sizes — only the code region below it grows or shrinks.
const KV_RESERVED: u32 = (1408 + 128) * 1024;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // memory.x: the checked-in script is the 4 MB layout; for any other
    // FLASH_SIZE we splice a recomputed MEMORY block (code = flash − KV) into it.
    let flash_size = resolve_flash_size();
    let template = std::fs::read_to_string("memory.x").expect("read memory.x");
    let memory_x = if flash_size == DEFAULT_FLASH_SIZE {
        template
    } else {
        splice_memory_block(&template, flash_size)
    };
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(memory_x.as_bytes())
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=PK_FLASH_SIZE={flash_size}");
    println!("cargo:rerun-if-env-changed=FLASH_SIZE");

    let (vid, pid, manufacturer, product) = resolve_identity();
    println!("cargo:rustc-env=PK_USB_VID={vid}");
    println!("cargo:rustc-env=PK_USB_PID={pid}");
    println!("cargo:rustc-env=PK_USB_MANUFACTURER={manufacturer}");
    println!("cargo:rustc-env=PK_USB_PRODUCT={product}");
    println!("cargo:rerun-if-env-changed=VIDPID");
    println!("cargo:rerun-if-env-changed=USB_VID");
    println!("cargo:rerun-if-env-changed=USB_PID");
    println!("cargo:rerun-if-env-changed=USB_MANUFACTURER");
    println!("cargo:rerun-if-env-changed=USB_PRODUCT");

    println!(
        "cargo:rustc-env=PK_XOSC_DELAY_MULT={}",
        resolve_xosc_delay_mult()
    );
    println!("cargo:rerun-if-env-changed=XOSC_DELAY_MULT");

    // WS2812 data pin (default GPIO16, the Waveshare RP2350-One). Chosen at
    // compile time because embassy's `PioPin` is implemented per concrete pin
    // (no `AnyPin`), so a runtime pin can't reach the PIO state machine.
    let led_pin = resolve_led_pin();
    println!("cargo:rustc-cfg=led_pin=\"{led_pin}\"");
    let values = (0..=29u8)
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo:rustc-check-cfg=cfg(led_pin, values({values}))");
    println!("cargo:rerun-if-env-changed=LED_PIN");

    // LED backend (default `ws2812`, the Waveshare RP2350-One). Selected at
    // compile time so only the chosen driver — and its dependencies (PIO, PWM) —
    // is built. `gpio` = a plain on/off indicator, `pimoroni` = a 3-pin PWM RGB
    // (Pimoroni Tiny 2350), `none` = headless.
    let led_kind = resolve_led_kind();
    println!("cargo:rustc-cfg=led_kind=\"{led_kind}\"");
    println!(
        "cargo:rustc-check-cfg=cfg(led_kind, values(\"ws2812\", \"gpio\", \"pimoroni\", \"none\"))"
    );
    println!("cargo:rerun-if-env-changed=LED_KIND");

    // WS2812 wire byte order (the `ws2812` backend only): `rgb` (default — the
    // Waveshare RP2350-One is unusually RGB) or `grb` (the WS2812B standard, e.g.
    // the TenStar RP2350-USB). The wrong order swaps red↔green (blue is fine).
    let led_order = resolve_led_order();
    println!("cargo:rustc-cfg=led_order=\"{led_order}\"");
    println!("cargo:rustc-check-cfg=cfg(led_order, values(\"rgb\", \"grb\"))");
    println!("cargo:rerun-if-env-changed=LED_ORDER");

    // Bake fake OTP keys into the image instead of reading the fuses — exercises
    // the kbase migration + boot path without an irreversible OTP write.
    // TEST BUILDS ONLY; never set for a shipped image.
    for (env_var, baked) in [("FAKE_MKEK", "PK_FAKE_MKEK"), ("FAKE_DEVK", "PK_FAKE_DEVK")] {
        if let Some(hex) = resolve_fake_key(env_var) {
            println!("cargo:rustc-env={baked}={hex}");
            println!("cargo:warning={env_var} baked into this image — TEST BUILD ONLY, never ship");
        }
        println!("cargo:rerun-if-env-changed={env_var}");
    }
}

/// Resolve `FLASH_SIZE` to a byte count. Accepts a decimal byte count, `0xHEX`,
/// or a `<n>K`/`<n>KB`/`<n>M`/`<n>MB` suffix; defaults to 4 MB. Must be
/// sector-aligned, leave room for the KV store, and stay within 16 MB.
fn resolve_flash_size() -> u32 {
    let raw = env::var("FLASH_SIZE").unwrap_or_else(|_| DEFAULT_FLASH_SIZE.to_string());
    let bytes = parse_size(raw.trim())
        .unwrap_or_else(|| panic!("FLASH_SIZE={raw:?} — use a byte count, 0xHEX, or <n>K / <n>M"));
    assert!(
        bytes.is_multiple_of(4096),
        "FLASH_SIZE={bytes} must be a multiple of 4096 (the QSPI erase sector)"
    );
    assert!(
        bytes > KV_RESERVED,
        "FLASH_SIZE={bytes} too small — {KV_RESERVED} bytes are reserved for the KV store"
    );
    assert!(
        bytes <= 16 * 1024 * 1024,
        "FLASH_SIZE={bytes} exceeds the supported 16 MiB"
    );
    bytes
}

/// Parse `123`, `0x10000`, `512K`, `4M`, `4MB`, … into a byte count.
fn parse_size(s: &str) -> Option<u32> {
    let lower = s.to_ascii_lowercase();
    let (digits, mult) = if let Some(n) = lower.strip_suffix("mb").or(lower.strip_suffix('m')) {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kb").or(lower.strip_suffix('k')) {
        (n, 1024)
    } else {
        (lower.as_str(), 1)
    };
    let digits = digits.trim();
    let base = match digits.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    base.checked_mul(mult)
}

/// Recompute the `MEMORY { … }` block for a non-default flash size and splice it
/// into the template, keeping the rest (KV symbols, SECTIONS) verbatim. The KV
/// store stays a fixed [`KV_RESERVED`] at the top; the code region is the rest.
fn splice_memory_block(template: &str, flash_size: u32) -> String {
    let code = flash_size - KV_RESERVED;
    let kvmain = 0x1000_0000 + code;
    let kvcnt = kvmain + 1408 * 1024;
    let block = format!(
        "MEMORY {{\n    \
         FLASH  : ORIGIN = 0x10000000, LENGTH = {}K\n    \
         KVMAIN : ORIGIN = {:#010X}, LENGTH = 1408K\n    \
         KVCNT  : ORIGIN = {:#010X}, LENGTH = 128K\n    \
         RAM    : ORIGIN = 0x20000000, LENGTH = 512K\n}}",
        code / 1024,
        kvmain,
        kvcnt
    );
    let start = template
        .find("MEMORY {")
        .expect("memory.x: no MEMORY block");
    let close = template[start..]
        .find('}')
        .expect("memory.x: unterminated MEMORY");
    format!(
        "{}{}{}",
        &template[..start],
        block,
        &template[start + close + 1..]
    )
}

/// Resolve `LED_PIN` (the WS2812 data GPIO) to a number; defaults to 16. Limited
/// to the RP2350A range; point it at a free GPIO to keep the indicator off a pin
/// your board needs.
fn resolve_led_pin() -> u8 {
    let raw = env::var("LED_PIN").unwrap_or_else(|_| "16".into());
    let v = raw
        .trim()
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("LED_PIN={raw:?} must be a GPIO number 0..=29"));
    assert!(v <= 29, "LED_PIN={v} out of range 0..=29 (RP2350A GPIOs)");
    v
}

/// Resolve `LED_KIND` (the LED driver backend) to a known value; defaults to
/// `ws2812`. One of: `ws2812` (addressable RGB on `LED_PIN`), `gpio` (a plain
/// on/off LED on `LED_PIN`), `pimoroni` (3-pin PWM RGB, Pimoroni Tiny 2350), or
/// `none` (no indicator).
fn resolve_led_kind() -> String {
    let raw = env::var("LED_KIND").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "ws2812" => "ws2812".into(), // unset / empty → the default backend
        "gpio" | "pimoroni" | "none" => v,
        _ => panic!("LED_KIND={raw:?} must be one of: ws2812, gpio, pimoroni, none"),
    }
}

/// Resolve `LED_ORDER` (the WS2812 wire byte order) to `rgb` or `grb`; defaults
/// to `rgb` (the Waveshare RP2350-One). `grb` is the WS2812B standard — pick it
/// on boards whose red/green come out swapped (e.g. the TenStar RP2350-USB).
fn resolve_led_order() -> String {
    let raw = env::var("LED_ORDER").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "rgb" => "rgb".into(), // unset / empty → the Waveshare default
        "grb" => v,
        _ => panic!("LED_ORDER={raw:?} must be rgb or grb"),
    }
}

/// Validate a fake-OTP-key env var: exactly 64 hex chars (32 bytes), returned
/// lowercased. Anything else fails the build — a silently truncated key would
/// "work" while sealing data under the wrong root.
fn resolve_fake_key(var: &str) -> Option<String> {
    let v = env::var(var).ok()?;
    if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("{var} must be exactly 64 hex chars (32 bytes), got {v:?}");
    }
    Some(v.to_ascii_lowercase())
}

/// Resolve the XOSC startup-delay multiplier (`XOSC_DELAY_MULT`, default 128 =
/// the embassy default). A larger multiplier lengthens the crystal-oscillator
/// settle wait before the chip runs from it, hardening the early-boot /
/// clock-switch window against glitch / fault injection. Range 1..=1024: embassy
/// stores the derived startup count as a `u16`, which a larger multiplier would
/// overflow for the 12 MHz crystal.
fn resolve_xosc_delay_mult() -> u32 {
    let raw = env::var("XOSC_DELAY_MULT").unwrap_or_else(|_| "128".into());
    let v = raw
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("XOSC_DELAY_MULT={raw:?} is not a positive integer"));
    assert!(
        (1..=1024).contains(&v),
        "XOSC_DELAY_MULT={v} out of range 1..=1024"
    );
    v
}

/// Resolve the full USB identity `(VID, PID, manufacturer, product)`.
///
/// `VIDPID=<preset>` picks a named VID/PID pair; the default `RSKey` is this
/// project's own pid.codes identity (`0x1209:0x0001`). `USB_VID` / `USB_PID`
/// (`0xHHHH` or decimal) override either half, and `USB_MANUFACTURER` /
/// `USB_PRODUCT` override the descriptor strings.
///
/// The descriptor strings follow the resolved VID: the default build presents
/// this project's own identity (manufacturer `RS-Key`, product `RS-Key Security
/// Key`) and is NOT a masquerade. The Yubico VID (`0x1050`) instead swaps in the
/// `Yubico` / `YubiKey …` strings, because `ykman` / Yubico Authenticator derive
/// the device's PID *purely from the PC/SC reader name* (it must contain "Yubico
/// YubiKey"). That is an opt-in local-interop flavor — built by the interop suite
/// / CI matrix only — never for distribution.
fn resolve_identity() -> (u16, u16, String, String) {
    let preset = env::var("VIDPID").unwrap_or_else(|_| "RSKey".into());
    let (mut vid, mut pid) = match preset.as_str() {
        // This project's own pid.codes identity — the default.
        "RSKey" => (0x1209, 0x0001),
        // Vendor-mimicking interop presets (opt-in; local interop only, never
        // distributed). Only the Yubico VID also swaps the descriptor strings.
        "NitroHSM" => (0x20A0, 0x4230),
        "NitroFIDO2" => (0x20A0, 0x42B1),
        "NitroStart" => (0x20A0, 0x4211),
        "NitroPro" => (0x20A0, 0x4108),
        "Nitro3" => (0x20A0, 0x42B2),
        "Yubikey5" => (0x1050, 0x0407),
        "YubikeyNeo" => (0x1050, 0x0116),
        "YubiHSM" => (0x1050, 0x0030),
        "Gnuk" => (0x234B, 0x0000),
        "GnuPG" => (0x1209, 0x2440),
        // Raspberry Pi VID fallback and a non-colliding dev placeholder.
        "Pico" => (0x2E8A, 0x10FD),
        "Dev" => (0xFEFF, 0xFCFD),
        other => panic!(
            "unknown VIDPID preset {other:?}; known: RSKey, NitroHSM, NitroFIDO2, \
             NitroStart, NitroPro, Nitro3, Yubikey5, YubikeyNeo, YubiHSM, Gnuk, GnuPG, \
             Pico, Dev (or set USB_VID / USB_PID directly)"
        ),
    };
    if let Ok(v) = env::var("USB_VID") {
        vid = parse_u16(&v, "USB_VID");
    }
    if let Ok(p) = env::var("USB_PID") {
        pid = parse_u16(&p, "USB_PID");
    }

    // Descriptor strings track the resolved VID: this project's own identity by
    // default; the Yubico VID gets the masquerade strings so the PC/SC reader
    // name carries "Yubico YubiKey" for ykman / Yubico Authenticator.
    let (mut manufacturer, mut product) = if vid == 0x1050 {
        (
            "Yubico".to_string(),
            "YubiKey RSK OTP+FIDO+CCID".to_string(),
        )
    } else {
        ("RS-Key".to_string(), "RS-Key Security Key".to_string())
    };
    if let Ok(m) = env::var("USB_MANUFACTURER") {
        manufacturer = m;
    }
    if let Ok(p) = env::var("USB_PRODUCT") {
        product = p;
    }
    (vid, pid, manufacturer, product)
}

/// Parse a `0xHHHH` (or decimal) 16-bit value from an env override.
fn parse_u16(s: &str, var: &str) -> u16 {
    let s = s.trim();
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    let v = parsed.unwrap_or_else(|_| panic!("{var}={s:?} is not a 0xHHHH or decimal number"));
    assert!(v <= 0xFFFF, "{var}={s:?} exceeds 16 bits");
    v as u16
}
