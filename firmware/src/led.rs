// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! LED status engine: each status (boot/processing/touch/idle) has a fixed blink
//! timing plus a runtime-configurable color/brightness persisted in `EF_LED_CONF`.
//! The blink task runs on the high-priority interrupt executor, so the LED keeps
//! animating while the worker blocks in a touch wait or long synchronous crypto.
//!
//! The status engine is backend-agnostic — it keeps a colour/brightness per
//! status in atomics. The render half is chosen at build time by `LED_KIND`:
//! [`Blinker::tick`] computes the colour to show each tick, and one of the
//! `*_task`s drives the hardware — `ws2812` (addressable RGB), `gpio` (a plain
//! on/off LED, colour collapsed to lit/unlit), `pimoroni` (3-pin PWM RGB), or
//! `none` (no indicator).

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(not(led_kind = "none"))]
use embassy_time::{Duration, Instant, Timer};
#[cfg(not(led_kind = "none"))]
use smart_leds::RGB8;

// The Waveshare RP2350-One's WS2812 takes the RGB wire byte order, not the
// WS2812B-standard GRB embassy defaults to — the default swaps red and green on
// this board (blue is unaffected). Drive it in `Rgb` order to match.
#[cfg(led_kind = "ws2812")]
use embassy_rp::peripherals::PIO0;
#[cfg(led_kind = "ws2812")]
use embassy_rp::pio_programs::ws2812::{PioWs2812, Rgb};

#[cfg(led_kind = "gpio")]
use embassy_rp::gpio::{Level, Output};

#[cfg(led_kind = "pimoroni")]
use embassy_rp::pwm::{Config as PwmConfig, Pwm};

/// The Waveshare RP2350-One has a single on-board WS2812 (GPIO16).
#[cfg(led_kind = "ws2812")]
pub const NUM_LEDS: usize = 1;

/// Status indices — also the index into [`TIMING`]/[`DEFAULT_COLOR`], the
/// per-status atomics, and the `EF_LED_CONF` layout.
pub const STATUS_IDLE: u8 = 0;
pub const STATUS_PROCESSING: u8 = 1;
/// Only set from the (gated) touch-wait path.
#[cfg_attr(not(feature = "up-button"), allow(dead_code))]
pub const STATUS_TOUCH: u8 = 2;
pub const STATUS_BOOT: u8 = 3;
const N_STATUS: usize = 4;

// Color codes; 0 = off.
const COLOR_RED: u8 = 1;
const COLOR_GREEN: u8 = 2;
#[allow(dead_code)]
const COLOR_BLUE: u8 = 3;
const COLOR_YELLOW: u8 = 4;

/// Fixed blink timing per status `(on_ms, off_ms)` — only color and brightness
/// are configurable. Indexed by the `STATUS_*` constants.
#[cfg(not(led_kind = "none"))]
const TIMING: [(u64, u64); N_STATUS] = [
    (500, 500),  // Idle
    (50, 50),    // Processing
    (1000, 100), // Touch
    (500, 500),  // Boot
];
/// Default color per status (indexed by the `STATUS_*` constants).
const DEFAULT_COLOR: [u8; N_STATUS] = [COLOR_GREEN, COLOR_GREEN, COLOR_YELLOW, COLOR_RED];
/// Default channel max (a gentle 16/255).
const DEFAULT_BRIGHTNESS: u8 = 16;

/// `EF_LED_CONF` byte layout: `[steady, (color, brightness) × N_STATUS]`.
pub const CONF_LEN: usize = 1 + 2 * N_STATUS;

static LED_STATUS: AtomicU8 = AtomicU8::new(STATUS_BOOT);
/// When set, the blink task ignores the on/off phases and shows the current
/// status color solidly — the status still recolors the LED, it just stops
/// blinking. Off by default.
static LED_STEADY: AtomicBool = AtomicBool::new(false);
static STATUS_COLOR: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_COLOR[STATUS_IDLE as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_PROCESSING as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_TOUCH as usize]),
    AtomicU8::new(DEFAULT_COLOR[STATUS_BOOT as usize]),
];
static STATUS_BRIGHTNESS: [AtomicU8; N_STATUS] = [
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
    AtomicU8::new(DEFAULT_BRIGHTNESS),
];

/// Set the active status (the worker on dispatch start/end, `presence` for a
/// touch wait). Out-of-range indices are clamped by the render loop.
pub fn set_status(idx: u8) {
    LED_STATUS.store(idx, Ordering::Relaxed);
}

/// The active status index — saved/restored around a touch wait by `presence`.
#[cfg_attr(not(feature = "up-button"), allow(dead_code))]
pub fn status() -> u8 {
    LED_STATUS.load(Ordering::Relaxed)
}

/// Override one status's color (0–7) and brightness (0–255, 0 = off); used by the
/// vendor SET LED command.
pub fn set_status_config(idx: u8, color: u8, brightness: u8) {
    let i = (idx as usize).min(N_STATUS - 1);
    STATUS_COLOR[i].store(color & 0x7, Ordering::Relaxed);
    STATUS_BRIGHTNESS[i].store(brightness, Ordering::Relaxed);
}

/// Toggle the global no-blink (solid) mode.
pub fn set_steady(on: bool) {
    LED_STEADY.store(on, Ordering::Relaxed);
}

/// The full config as the persisted/`GET LED` block `[steady, (color, br) × N]`.
pub fn config_block() -> [u8; CONF_LEN] {
    let mut b = [0u8; CONF_LEN];
    b[0] = LED_STEADY.load(Ordering::Relaxed) as u8;
    for i in 0..N_STATUS {
        b[1 + 2 * i] = STATUS_COLOR[i].load(Ordering::Relaxed);
        b[2 + 2 * i] = STATUS_BRIGHTNESS[i].load(Ordering::Relaxed);
    }
    b
}

/// Apply a config block (boot from flash / SET LED). A short buffer is treated as
/// a legacy record: `[brightness, idle_color]` or `[brightness, idle_color,
/// steady]`, mapped onto the idle status so an upgrade keeps the old look.
pub fn load_block(b: &[u8]) {
    if b.len() < CONF_LEN {
        if b.len() >= 2 {
            STATUS_BRIGHTNESS[STATUS_IDLE as usize].store(b[0], Ordering::Relaxed);
            STATUS_COLOR[STATUS_IDLE as usize].store(b[1] & 0x7, Ordering::Relaxed);
        }
        if b.len() >= 3 {
            LED_STEADY.store(b[2] != 0, Ordering::Relaxed);
        }
        return;
    }
    LED_STEADY.store(b[0] != 0, Ordering::Relaxed);
    for i in 0..N_STATUS {
        STATUS_COLOR[i].store(b[1 + 2 * i] & 0x7, Ordering::Relaxed);
        STATUS_BRIGHTNESS[i].store(b[2 + 2 * i], Ordering::Relaxed);
    }
}

/// Map a status colour code (0–7) at channel max `b` to an RGB triple.
#[cfg(not(led_kind = "none"))]
fn color_rgb(color: u8, b: u8) -> RGB8 {
    let (r, g, bl) = match color {
        COLOR_RED => (b, 0, 0),
        COLOR_GREEN => (0, b, 0),
        COLOR_BLUE => (0, 0, b),
        COLOR_YELLOW => (b, b, 0),
        5 => (b, 0, b), // magenta
        6 => (0, b, b), // cyan
        7 => (b, b, b), // white
        _ => (0, 0, 0), // off
    };
    RGB8 { r, g, b: bl }
}

/// Tracks the blink phase and yields the colour to show each tick — shared by
/// every render backend. The status, colour and brightness are re-read every
/// tick so a mid-phase switch (touch wait, processing) recolors immediately. A
/// phase already underway keeps its length; in steady mode the timing still
/// advances (so toggling back to blinking resumes cleanly) but the colour stays
/// lit the whole phase.
#[cfg(not(led_kind = "none"))]
struct Blinker {
    on_phase: bool,
    phase_end: Instant,
}

#[cfg(not(led_kind = "none"))]
impl Blinker {
    fn new() -> Self {
        Self {
            on_phase: false,
            phase_end: Instant::now(),
        }
    }

    fn tick(&mut self) -> RGB8 {
        let s = (LED_STATUS.load(Ordering::Relaxed) as usize).min(N_STATUS - 1);
        let (on_ms, off_ms) = TIMING[s];
        let now = Instant::now();
        if now >= self.phase_end {
            self.on_phase = !self.on_phase;
            self.phase_end =
                now + Duration::from_millis(if self.on_phase { on_ms } else { off_ms });
        }
        if self.on_phase || LED_STEADY.load(Ordering::Relaxed) {
            color_rgb(
                STATUS_COLOR[s].load(Ordering::Relaxed),
                STATUS_BRIGHTNESS[s].load(Ordering::Relaxed),
            )
        } else {
            RGB8::default()
        }
    }
}

/// `ws2812` backend: drive the single addressable LED with the blink colour.
#[cfg(led_kind = "ws2812")]
#[embassy_executor::task]
pub async fn ws2812_task(mut ws2812: PioWs2812<'static, PIO0, 0, NUM_LEDS, Rgb>) {
    let mut blinker = Blinker::new();
    loop {
        ws2812.write(&[blinker.tick(); NUM_LEDS]).await;
        Timer::after_millis(5).await;
    }
}

/// `gpio` backend: a plain on/off LED (active-high). Hue and brightness collapse
/// to lit/unlit — only the blink *pattern* distinguishes statuses.
#[cfg(led_kind = "gpio")]
#[embassy_executor::task]
pub async fn gpio_task(mut led: Output<'static>) {
    let mut blinker = Blinker::new();
    loop {
        let c = blinker.tick();
        led.set_level(if (c.r | c.g | c.b) != 0 {
            Level::High
        } else {
            Level::Low
        });
        Timer::after_millis(5).await;
    }
}

/// `pimoroni` backend: a 3-pin PWM RGB LED (Pimoroni Tiny 2350 — R=GPIO18,
/// G=GPIO19, B=GPIO20; common-anode, so the channels are inverted). `rg` drives
/// R (channel A) + G (channel B) on one slice, `b` drives B (channel A) on
/// another; `top` = 255 so a colour byte maps straight onto a compare value.
#[cfg(led_kind = "pimoroni")]
#[embassy_executor::task]
pub async fn pimoroni_task(mut rg: Pwm<'static>, mut b: Pwm<'static>) {
    let mut blinker = Blinker::new();
    loop {
        let c = blinker.tick();
        let mut cfg = pimoroni_cfg();
        cfg.compare_a = u16::from(c.r);
        cfg.compare_b = u16::from(c.g);
        rg.set_config(&cfg);
        let mut cfg_b = pimoroni_cfg();
        cfg_b.compare_a = u16::from(c.b);
        b.set_config(&cfg_b);
        Timer::after_millis(5).await;
    }
}

/// Base PWM config for the Pimoroni common-anode RGB: an 8-bit `top`, both
/// channels inverted (the LED lights when the pin is driven low / sinks current).
/// Shared by the task and `main`'s `Pwm` construction so the polarity matches.
#[cfg(led_kind = "pimoroni")]
pub fn pimoroni_cfg() -> PwmConfig {
    // `PwmConfig` is `#[non_exhaustive]`, so build from Default and set fields.
    let mut cfg = PwmConfig::default();
    cfg.top = 255;
    cfg.invert_a = true;
    cfg.invert_b = true;
    cfg
}

/// USB device-event handler: flip the boot status to idle the moment the host
/// *configures* the device, so the LED shows "enumerated & ready" (green) rather
/// than staying on the red boot status until the first application command. On a
/// host with no PC/SC daemon (and nothing else probing the key) that first
/// command may never arrive even though the key is healthy and enumerated, which
/// looked like a hang. The worker still drives processing/idle per command.
pub struct StatusHandler;

impl embassy_usb::Handler for StatusHandler {
    fn configured(&mut self, configured: bool) {
        set_status(if configured { STATUS_IDLE } else { STATUS_BOOT });
    }
}
