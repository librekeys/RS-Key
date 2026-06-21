// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-fido` — the FIDO2 (CTAP2) + U2F (CTAP1) applet. The logic is pure and
//! host-testable: the device seed, serial, RNG and flash come from the caller
//! ([`Ctx`]), never from globals; `firmware` wires in the RP2350 TRNG and flash.

// Only the ML-DSA-44 credential key is heap-boxed (its ~17 KB of fips204 NTT-form
// keys would otherwise sit on the worker stack right below the stack-heavy sign;
// see `ec::CredKey`). The firmware provides the heap; everything else stays
// no-alloc.
extern crate alloc;

pub mod cbordec;
pub mod cert;
pub mod clientpin;
pub mod config;
pub mod consts;
pub mod cose;
pub mod credential;
pub mod credmgmt;
pub mod ec;
pub mod error;
pub mod getassertion;
pub mod getinfo;
pub mod hmacsecret;
pub mod journal;
pub mod keyderiv;
pub mod largeblobs;
pub mod makecredential;
pub mod reset;
pub mod seed;
pub mod selection;
pub mod state;
pub mod u2f;
pub mod vendor;

pub use error::{CTAP2_OK, CtapError, CtapResult};

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};

pub use state::FidoState;

/// A source of random bytes — the device TRNG in `firmware`, a deterministic
/// stream in tests. Decouples the FIDO logic from any specific `rand_core` version.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Outcome of asking for physical user presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The user touched the device.
    Confirmed,
    /// No touch within the timeout.
    Timeout,
    /// The user actively declined (no decline path on the BOOTSEL button today,
    /// but tests and other front-ends can produce it → `OPERATION_DENIED`).
    Declined,
    /// The platform sent `CTAPHID_CANCEL` while the touch was awaited; the
    /// in-flight CTAP2 command must answer `CTAP2_ERR_KEEPALIVE_CANCEL`.
    Cancelled,
}

/// Obtains physical user presence. The firmware polls the BOOTSEL button; with
/// no button configured it confirms immediately, which is also what host tests
/// use via [`AlwaysConfirm`].
pub trait UserPresence {
    fn request(&mut self) -> Presence;
}

/// A [`UserPresence`] that confirms instantly — the no-button default and the
/// host-test stand-in.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self) -> Presence {
        Presence::Confirmed
    }
}

/// Per-request context the firmware threads into the FIDO commands: the device
/// identity, the flash file system, an RNG, the cross-message PIN/UV state and
/// the current uptime.
pub struct Ctx<'a, S: Storage, R: Rng> {
    pub dev: Device<'a>,
    pub fs: &'a mut Fs<S>,
    pub rng: &'a mut R,
    pub state: &'a mut FidoState,
    /// Device uptime at request time — the credential creation timestamp.
    pub now_ms: u64,
    /// Physical user-presence source (BOOTSEL button); [`AlwaysConfirm`] when no
    /// button is configured or in tests.
    pub presence: &'a mut dyn UserPresence,
}

impl<S: Storage, R: Rng> Ctx<'_, S, R> {
    /// Request a touch, mapping any non-confirmation (timeout, decline or
    /// cancel) to `false`. Callers that must distinguish a `CTAPHID_CANCEL`
    /// (→ `KEEPALIVE_CANCEL`) use [`require_presence`](Self::require_presence).
    pub fn check_user_presence(&mut self) -> bool {
        self.presence.request() == Presence::Confirmed
    }

    /// Obtain user presence for a CTAP2 command, mapping the outcome to its
    /// status code: a `CTAPHID_CANCEL` aborts with `KEEPALIVE_CANCEL`, any
    /// other non-confirmation (timeout, decline) with `OPERATION_DENIED`.
    pub fn require_presence(&mut self) -> Result<(), CtapError> {
        match self.presence.request() {
            Presence::Confirmed => Ok(()),
            Presence::Cancelled => Err(CtapError::KeepAliveCancel),
            Presence::Timeout | Presence::Declined => Err(CtapError::OperationDenied),
        }
    }

    /// The device seed for FIDO operations: the RAM copy a vendor `UNLOCK` left
    /// behind wins over flash; on a soft-locked device with no unlock this
    /// session, both fail and the operation errors out — that is the lock.
    pub fn load_keydev(&mut self) -> Option<[u8; 32]> {
        self.state
            .keydev_dec
            .or_else(|| seed::load_keydev(&self.dev, self.fs))
    }
}

/// Dispatch one CTAPHID_CBOR message: `data` is `command_byte ‖ cbor_params`.
///
/// Writes the response — one status byte then, on success, the CBOR payload —
/// into `out` and returns its length.
pub fn process_cbor<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, data: &[u8], out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    // Empty CTAPHID_CBOR is CTAP1_ERR_INVALID_LENGTH.
    let Some((&cmd, params)) = data.split_first() else {
        out[0] = CtapError::InvalidLength.as_u8();
        return 1;
    };

    let result = match cmd {
        consts::CTAP_GET_INFO => {
            // minPINLength / forceChangePin come from EF_MINPINLEN ([len, force]).
            let mut mp = [0u8; 2];
            let (min_pin, force) = match ctx.fs.read(consts::EF_MINPINLEN, &mut mp) {
                Some(n) if n >= 1 => (mp[0], n >= 2 && mp[1] == 1),
                _ => (consts::MIN_PIN_LENGTH, false),
            };
            let remaining_rk = credential::remaining_discoverable(ctx.fs);
            getinfo::get_info(
                ctx.fs.has_data(consts::EF_PIN),
                min_pin,
                force,
                ctx.fs.has_data(consts::EF_EA_ENABLED),
                ctx.fs.has_data(consts::EF_ALWAYS_UV),
                remaining_rk,
                &mut out[1..],
            )
        }
        consts::CTAP_MAKE_CREDENTIAL => makecredential::make_credential(ctx, params, &mut out[1..]),
        consts::CTAP_GET_ASSERTION => getassertion::get_assertion(ctx, params, &mut out[1..]),
        consts::CTAP_GET_NEXT_ASSERTION => getassertion::get_next_assertion(ctx, &mut out[1..]),
        consts::CTAP_CLIENT_PIN => clientpin::client_pin(ctx, params, &mut out[1..]),
        consts::CTAP_RESET => reset::reset(ctx),
        consts::CTAP_SELECTION => selection::selection(ctx),
        consts::CTAP_CONFIG => config::authenticator_config(ctx, params, &mut out[1..]),
        consts::CTAP_CREDENTIAL_MGMT => credmgmt::cred_mgmt(ctx, params, &mut out[1..]),
        consts::CTAP_LARGE_BLOBS => largeblobs::large_blobs(ctx, params, &mut out[1..]),
        consts::CTAP_VENDOR => vendor::vendor(ctx, params, &mut out[1..]),
        _ => Err(CtapError::InvalidCommand),
    };

    match result {
        Ok(n) => {
            out[0] = CTAP2_OK;
            1 + n
        }
        Err(e) => {
            out[0] = e.as_u8();
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    // Run process_cbor with a fresh context (empty flash).
    fn dispatch(data: &[u8], out: &mut [u8]) -> usize {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        let mut state = FidoState::new();
        let mut presence = AlwaysConfirm;
        let mut ctx = Ctx {
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
            presence: &mut presence,
        };
        process_cbor(&mut ctx, data, out)
    }

    #[test]
    fn dispatch_get_info_ok() {
        let mut out = [0u8; 512];
        let n = dispatch(&[consts::CTAP_GET_INFO], &mut out);
        assert!(n > 1);
        assert_eq!(out[0], CTAP2_OK);
        // The payload is the getInfo map (CBOR map header 0xB4 = map(20)).
        assert_eq!(out[1], 0xB4);
    }

    #[test]
    fn dispatch_unknown_command() {
        let mut out = [0u8; 64];
        let n = dispatch(&[0xEE], &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], CtapError::InvalidCommand.as_u8());
    }

    #[test]
    fn dispatch_empty_is_invalid_length() {
        let mut out = [0u8; 64];
        let n = dispatch(&[], &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], CtapError::InvalidLength.as_u8());
    }

    #[test]
    fn dispatch_get_assertion_routes_to_handler() {
        // getAssertion with empty params is malformed CBOR.
        let mut out = [0u8; 64];
        let n = dispatch(&[consts::CTAP_GET_ASSERTION], &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], CtapError::InvalidCbor.as_u8());
    }
}
