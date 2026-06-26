// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Physical user presence over either the BOOTSEL button (default) or a dedicated
//! GPIO button. BOOTSEL samples use the QSPI-CS-to-Hi-Z trick in a RAM function;
//! a GPIO button is polled as active-low with an internal pull-up. The wait blocks
//! the worker while the high-priority transports stream keepalives reporting
//! `UPNEEDED` ([`up_pending`]). One [`BootselPresence`] serves every applet's
//! `UserPresence` trait; a touch is required by default, and the opt-in `no-touch`
//! feature makes `request` confirm instantly (for the automated suites, which
//! cannot press a button).

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_rp::Peri;
use embassy_rp::gpio::{AnyPin, Input, Pull};
use embassy_rp::peripherals::BOOTSEL;

#[cfg(not(feature = "no-touch"))]
use embassy_rp::bootsel::is_bootsel_pressed;
#[cfg(not(feature = "no-touch"))]
use embassy_time::{Duration, Instant, block_for};

/// Set while the worker is blocked in a button wait — read by the CTAPHID keepalive
/// to report `UPNEEDED` (0x02) instead of `PROCESSING` (0x01).
static UP_PENDING: AtomicBool = AtomicBool::new(false);

/// Set by the CTAPHID transport (high-priority executor) when a `CTAPHID_CANCEL`
/// arrives for the request the worker is processing. The button wait — running on
/// the worker executor — polls it each iteration and abandons with `Cancelled`, so
/// the in-flight CTAP2 command answers `CTAP2_ERR_KEEPALIVE_CANCEL`. Cross-executor
/// (transport sets, worker reads), mirroring `UP_PENDING` in the other direction.
static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The CTAPHID keepalive hook passed to `CtapHid::new`: is a touch being awaited?
/// Always `false` on the `no-touch` build, so the status stays `PROCESSING`.
pub fn up_pending() -> bool {
    UP_PENDING.load(Ordering::Relaxed)
}

/// The CTAPHID cancel hook passed to `CtapHid::new`: request that an in-flight
/// touch wait be abandoned. Just sets the flag the wait polls (a no-op on the
/// no-button build, where `request` confirms instantly and never waits).
pub fn request_cancel() {
    CANCEL_REQUESTED.store(true, Ordering::Relaxed);
}

// Poll cadence and the press timeout. `block_for` keeps interrupts enabled, so the
// high-priority executor (USB + keepalives) runs between polls; only the ~4000-cycle
// `is_bootsel_pressed` read briefly masks interrupts.
#[cfg(not(feature = "no-touch"))]
const POLL_MS: u64 = 16;
#[cfg(not(feature = "no-touch"))]
const TIMEOUT_MS: u64 = 30_000;

/// Neutral wait result, mapped to each applet's own `Presence` enum. The button
/// has no "declined" gesture; `Cancelled` comes from a `CTAPHID_CANCEL` (FIDO
/// only) observed via [`CANCEL_REQUESTED`].
#[cfg(not(feature = "no-touch"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Confirmed,
    Timeout,
    Cancelled,
}

/// User presence via BOOTSEL (default) or a dedicated GPIO button.
pub struct BootselPresence {
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    button: Button,
}

#[cfg_attr(feature = "no-touch", allow(dead_code))]
enum Button {
    Bootsel(Peri<'static, BOOTSEL>),
    Gpio(Input<'static>),
}

impl BootselPresence {
    /// Build the default BOOTSEL-backed presence source.
    pub fn new_bootsel(bootsel: Peri<'static, BOOTSEL>) -> Self {
        Self {
            button: Button::Bootsel(bootsel),
        }
    }

    /// Build a GPIO-backed presence source on `pin` (active-low, pull-up).
    ///
    /// # Panics
    ///
    /// Panics if `pin` is out of the RP2350A range `0..=29`.
    pub fn new_gpio(pin: u8) -> Self {
        assert!(
            pin <= 29,
            "PRESENCE_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
        );
        // Safety: `main` guarantees this pin is not handed to another driver.
        let any = unsafe { AnyPin::steal(pin) };
        let input = Input::new(any, Pull::Up);
        Self {
            button: Button::Gpio(input),
        }
    }

    #[cfg(not(feature = "no-touch"))]
    fn pressed(&mut self) -> bool {
        match &mut self.button {
            Button::Bootsel(bootsel) => is_bootsel_pressed(bootsel.reborrow()),
            Button::Gpio(button) => button.is_low(),
        }
    }

    /// One non-blocking sample of the active presence source, for the typed-ticket
    /// button watcher. On the `no-touch` build it never samples.
    pub fn poll_pressed(&mut self) -> bool {
        #[cfg(not(feature = "no-touch"))]
        {
            self.pressed()
        }
        #[cfg(feature = "no-touch")]
        {
            false
        }
    }

    #[cfg(not(feature = "no-touch"))]
    fn wait(&mut self) -> Outcome {
        // Save the LED status, show the touch status for the wait, restore after.
        let saved = crate::led::status();
        crate::led::set_status(crate::led::STATUS_TOUCH);
        // Drop any cancel left from an earlier (already-finished) request so this
        // wait starts clean.
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Relaxed);
        let start = Instant::now();
        // Wait for a press; a CTAPHID_CANCEL aborts it, and with neither in
        // TIMEOUT_MS it times out.
        let result = loop {
            if self.pressed() {
                break Outcome::Confirmed;
            }
            if CANCEL_REQUESTED.load(Ordering::Relaxed) {
                break Outcome::Cancelled;
            }
            if start.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
                break Outcome::Timeout;
            }
            block_for(Duration::from_millis(POLL_MS));
        };
        // Debounce: wait for release (bounded) so a held button doesn't
        // immediately satisfy the next operation.
        if result == Outcome::Confirmed {
            let release = Instant::now();
            while self.pressed() {
                if release.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
                    break;
                }
                block_for(Duration::from_millis(POLL_MS));
            }
        }
        UP_PENDING.store(false, Ordering::Relaxed);
        // Clear any cancel that raced in (e.g. just after a confirm) so it can't
        // leak into the next request's wait.
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        crate::led::set_status(saved);
        result
    }
}

impl rsk_fido::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_fido::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_fido::Presence::Confirmed,
                Outcome::Timeout => rsk_fido::Presence::Timeout,
                Outcome::Cancelled => rsk_fido::Presence::Cancelled,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_fido::Presence::Confirmed
        }
    }
}

impl rsk_openpgp::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_openpgp::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_openpgp::Presence::Confirmed,
                // OpenPGP UIF runs over CCID, which carries no CTAPHID_CANCEL, so
                // Cancelled is unreachable here; treat it as a non-confirmation.
                Outcome::Timeout | Outcome::Cancelled => rsk_openpgp::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_openpgp::Presence::Confirmed
        }
    }
}

impl rsk_otp::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_otp::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_otp::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_otp::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_otp::Presence::Confirmed
        }
    }
}

impl rsk_oath::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_oath::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_oath::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_oath::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_oath::Presence::Confirmed
        }
    }
}
