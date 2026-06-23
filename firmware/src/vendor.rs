// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vendor applet: a flash-persisted test counter, LED customization (SET/GET LED,
//! persisted in `EF_LED_CONF` and applied live), and the reboot command — which
//! is only queued here and run by the worker after the response has flushed.

use core::sync::atomic::{AtomicU8, Ordering};

use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Vendor AID (RID `F0 00 00 00`, app `01`).
pub const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];

/// Dynamic file holding the counter; `Fs::scan` rediscovers it after a reboot.
const COUNTER_FID: u16 = 0xCC01;
/// LED config block `[steady, (effect, color, brightness) × status]`; outside both reset
/// scopes (sticky). A legacy 2/3-byte record (pre-per-status firmware) is mapped
/// onto the idle status by [`crate::led::load_block`].
const EF_LED_CONF: u16 = 0x1123;
/// SET LED P2 bit that turns blinking off (solid color); the low 3 bits are the
/// color and bits 5:4 select which status is being configured.
const P2_STEADY: u8 = 0x08;

const INS_INCREMENT: u8 = 0x01;
const INS_GET: u8 = 0x02;
// SET LED: P1 = brightness (0–255), P2 = color(0–7) | steady(0x08) | status<<4.
const INS_SET_LED: u8 = 0x10;
const INS_GET_LED: u8 = 0x11;
// CORE1 STATS: 32 bytes LE — core1 wakes + jobs, candidates tried / primes
// found per core, entry-deadline misses, then the live flags (busy, stop,
// job-pending, degraded). The second core has no debugger and no UART; this
// is its only window.
const INS_CORE1_STATS: u8 = 0x12;
// KEYGEN MICROBENCH (debug builds only): time the two keygen hot primitives so
// the small-prime sieve can be sized against the modexp cost. P1 selects the
// primitive (0 = strong Miller-Rabin base 2, 1 = the full small-factor sieve),
// data = a candidate (little-endian, length a multiple of 32). Runs it
// BENCH_ITERS times and returns; the host times the whole APDU. Behind
// `keygen-bench` so it never ships.
#[cfg(feature = "keygen-bench")]
const INS_KEYGEN_BENCH: u8 = 0x13;
#[cfg(feature = "keygen-bench")]
const BENCH_ITERS: u32 = 400;
const INS_REBOOT: u8 = 0x1F; // P1: 0 = warm reboot, 1 = secure reboot to BOOTSEL

/// Pending reboot request: 0 = none, 1 = warm reboot,
/// 2 = secure reboot to the BOOTSEL bootloader. Set by [`INS_REBOOT`] and consumed
/// by the worker once the SW_OK response has been sent — the reset can't run inline
/// or the host never sees the reply.
static REBOOT: AtomicU8 = AtomicU8::new(0);

/// Take and clear any pending reboot request (the worker, after the response
/// flushes). `Some(1)` = warm reboot, `Some(2)` = secure reboot to BOOTSEL.
pub fn take_reboot() -> Option<u8> {
    match REBOOT.swap(0, Ordering::Relaxed) {
        0 => None,
        m => Some(m),
    }
}

/// Queue a reboot (also used by the rescue applet's REBOOT_BOOTSEL command).
pub fn request_reboot(bootsel: bool) {
    REBOOT.store(if bootsel { 2 } else { 1 }, Ordering::Relaxed);
}

pub struct VendorApplet;

impl<S: Storage> Applet<Fs<S>> for VendorApplet {
    fn aid(&self) -> &'static [u8] {
        VENDOR_AID
    }

    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, _res: &mut ResBuf) -> Sw {
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.ins {
            INS_GET => {
                res.extend(&read_counter(fs).to_be_bytes());
                Sw::OK
            }
            INS_INCREMENT => {
                let next = read_counter(fs).wrapping_add(1);
                if fs.put(COUNTER_FID, &next.to_be_bytes()).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                res.extend(&next.to_be_bytes());
                Sw::OK
            }
            INS_SET_LED => {
                // One status (P2 bits 5:4) gets P1 brightness + P2 color; the
                // steady bit is global. Optional data bytes set effect and speed.
                let status = (apdu.p2 >> 4) & 0x3;
                crate::led::set_status_config(status, apdu.p2 & 0x7, apdu.p1);
                crate::led::set_steady(apdu.p2 & P2_STEADY != 0);
                if apdu.nc >= 1 {
                    crate::led::set_status_effect(
                        status,
                        apdu.data[0],
                        apdu.data.get(1).copied().unwrap_or(0),
                    );
                }
                if fs.put(EF_LED_CONF, &crate::led::config_block()).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                Sw::OK
            }
            INS_GET_LED => {
                res.extend(&crate::led::config_block());
                Sw::OK
            }
            INS_CORE1_STATS => {
                res.extend(&crate::core1::stats());
                Sw::OK
            }
            #[cfg(feature = "keygen-bench")]
            INS_KEYGEN_BENCH => {
                let cand = apdu.data;
                if cand.is_empty() || !cand.len().is_multiple_of(32) || cand.len() > 256 {
                    return Sw::WRONG_LENGTH;
                }
                // `core::hint::black_box` keeps the loop from being optimized to
                // one iteration (the result is otherwise unused).
                use core::hint::black_box;
                match apdu.p1 {
                    0 => {
                        for _ in 0..BENCH_ITERS {
                            black_box(rsk_rsa_asm::passes_strong_mr_base2(black_box(cand)));
                        }
                    }
                    1 => {
                        for _ in 0..BENCH_ITERS {
                            black_box(rsk_rsa_asm::has_small_factor(black_box(cand)));
                        }
                    }
                    _ => return Sw::INCORRECT_P1P2,
                }
                res.extend(&BENCH_ITERS.to_le_bytes());
                Sw::OK
            }
            INS_REBOOT => {
                // Just record the request — the worker runs the secure wipe +
                // reset after this SW_OK reaches the host.
                if apdu.nc != 0 {
                    return Sw::WRONG_LENGTH;
                }
                match apdu.p1 {
                    0x00 => request_reboot(false),
                    0x01 => request_reboot(true),
                    _ => return Sw::INCORRECT_P1P2,
                }
                Sw::OK
            }
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Apply the LED config persisted in `EF_LED_CONF` (called by `main` on boot).
/// `load_block` tolerates a legacy 2/3-byte record from an older firmware.
pub fn load_led_config<S: Storage>(fs: &mut Fs<S>) {
    let mut buf = [0u8; crate::led::CONF_LEN];
    if let Some(n) = fs.read(EF_LED_CONF, &mut buf) {
        crate::led::load_block(&buf[..n.min(buf.len())]);
    }
}

fn read_counter<S: Storage>(fs: &mut Fs<S>) -> u32 {
    let mut buf = [0u8; 4];
    match fs.read(COUNTER_FID, &mut buf) {
        Some(n) if n >= 4 => u32::from_be_bytes(buf),
        _ => 0,
    }
}
