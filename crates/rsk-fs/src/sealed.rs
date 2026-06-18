// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Type-enforced chokepoint for at-rest secret key material.
//!
//! Every secret RS-Key persists — FIDO seeds, PIV/OpenPGP private keys, OATH
//! shared secrets, DEKs — must be cipher-sealed *before* it reaches flash: the
//! [`Storage`](crate::Storage) backend is plaintext, so a bare
//! `fs.put(fid, raw_secret)` would leave a recoverable secret on the chip.
//! Historically that rule held only by convention — a stray `fs.put` of a raw
//! key compiled fine. These two newtypes make it a compile-time property:
//!
//! * [`KeyFid`] names a slot that holds sealed secret material. It is *not* a
//!   `u16`, so the plaintext [`Fs::put`](crate::Fs::put) /
//!   [`Fs::read`](crate::Fs::read) cannot target a key slot — a careless
//!   `fs.put(EF_KEY_DEV, raw)` fails to compile. Key writes go through
//!   [`Fs::put_key`](crate::Fs::put_key), reads through
//!   [`Fs::read_key`](crate::Fs::read_key).
//! * [`Sealed`] is the only payload [`Fs::put_key`](crate::Fs::put_key)
//!   accepts. It is produced by [`Sealed::wrap`], which a seal routine calls on
//!   its cipher output. The wrap is deliberately loud and greppable: getting a
//!   raw secret into a key slot now reads `Sealed::wrap(raw)` at the call site,
//!   which no longer looks like an innocent `put`.
//!
//! The backend stays untyped (it is format-agnostic plaintext I/O); the
//! enforcement lives at the `Fs` API — the boundary every applet crosses.
//!
//! The compile-time guarantee, asserted: a key FID is a distinct type, so it
//! can never reach the plaintext `u16` file API (this must NOT build):
//!
//! ```compile_fail
//! use rsk_fs::KeyFid;
//! const SECRET_SLOT: KeyFid = KeyFid::new(0xCC00);
//! let _plain_fid: u16 = SECRET_SLOT; // KeyFid is not u16 — and `Fs::put` wants u16
//! ```
//!
//! Recovering the raw FID is always explicit and greppable:
//!
//! ```
//! use rsk_fs::KeyFid;
//! const SECRET_SLOT: KeyFid = KeyFid::new(0xCC00);
//! assert_eq!(SECRET_SLOT.get(), 0xCC00);
//! ```

/// A FID naming a slot that holds **sealed** secret key material.
///
/// Distinct from a plaintext `u16` FID precisely so the generic file API cannot
/// write or read it. Build one from a slot constant or a computed FID with
/// [`KeyFid::new`]; recover the raw FID with [`KeyFid::get`] only where a raw
/// FID is genuinely required (iterating a slot range during migration, say) —
/// prefer the typed [`Fs::put_key`](crate::Fs::put_key) /
/// [`Fs::read_key`](crate::Fs::read_key) API.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyFid(u16);

impl KeyFid {
    /// Name a key slot by its 16-bit FID.
    #[inline]
    pub const fn new(fid: u16) -> Self {
        KeyFid(fid)
    }

    /// The underlying 16-bit FID — an explicit, greppable escape hatch.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Cipher output on its way to a [`KeyFid`] slot — the only payload
/// [`Fs::put_key`](crate::Fs::put_key) accepts.
///
/// Borrows the sealed blob, whatever an applet's seal format is (`nonce ‖ ct ‖
/// tag`, a CBC/CFB ciphertext, …). [`Sealed::wrap`] is intentionally the only
/// constructor and intentionally loud: a seal routine calls it on the bytes it
/// just encrypted, so putting a secret into a key slot is always visible as
/// `Sealed::wrap(...)` at the call site. It is a marker, not a proof — it cannot
/// verify the bytes are genuinely ciphertext — but it removes the silent path,
/// and paired with [`KeyFid`] it makes the seal API the only route to a key
/// slot.
pub struct Sealed<'a>(&'a [u8]);

impl<'a> Sealed<'a> {
    /// Wrap freshly-sealed cipher output. Call at the end of a seal routine,
    /// never on a plaintext secret.
    #[inline]
    pub fn wrap(blob: &'a [u8]) -> Self {
        Sealed(blob)
    }

    /// The sealed bytes, for the one consumer that writes them to flash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }
}
