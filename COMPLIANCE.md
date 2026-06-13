# Licensing & compliance posture

A plain-language record of how RS-Key is licensed and why, and the
distribution assumptions that posture rests on. This is an engineering
compliance summary, not legal advice. See [LICENSE](LICENSE),
[NOTICE](NOTICE), and [third_party/README.md](third_party/README.md) for the
authoritative text.

## License: AGPL-3.0-only (and why it must be)

RS-Key is licensed **AGPL-3.0-only**. This is not a free choice — it is forced
by the upstream it derives from:

- RS-Key is a **behavioral reimplementation** of the pico-keys firmware family
  (pico-fido, pico-openpgp, pico-keys-sdk) by Pol Henarejos. The protocol
  behaviour, data-object layouts and applet semantics follow that work; the
  Rust code, the embassy runtime and the host tooling are original.
- Upstream pico-keys is **AGPL-3.0-only**. Verified directly from its source
  headers: every file reads *"under the terms of the GNU Affero General Public
  License as published by the Free Software Foundation, version 3"* — i.e.
  **"version 3"** with **no** *"or (at your option) any later version"* clause
  (checked across pico-fido / pico-openpgp / pico-keys-sdk: 0 of ~136 files
  carry an "or later" grant).

Consequences:

- RS-Key **inherits AGPL-3.0-only** and **cannot** be relicensed to
  AGPL-3.0-**or-later**, GPL, or any permissive license (MIT/Apache/BSD). The
  "relicense it proprietary later" move is legally unavailable here — by
  design. So must every fork remain AGPL-3.0-only.
- "Maximum permissiveness" for this project therefore means: add **no**
  restrictions beyond the AGPL (no CLA, no Commons Clause, no field-of-use
  limits) — which is already the case. The license version itself has no
  permissiveness lever to pull.

`rsk-wipe` is a Rust port of `pico-nuke` (GPL-3.0), itself derived from the
Raspberry Pi `pico-examples` `flash_nuke` utility (BSD-3-Clause); it is shipped
under AGPL-3.0-only, compatible with both upstreams.

## Source availability & build/install

RS-Key is source-available and self-buildable end to end:

- Full source is the public Git repository; every release's Corresponding
  Source is the tagged tree.
- Build: [docs/build.md](docs/build.md), or hermetically with
  `nix build .#firmware`.
- Flash: [docs/quickstart.md](docs/quickstart.md) /
  [docs/production.md](docs/production.md) (`picotool`, UF2).

## AGPL §13 (network interaction): not applicable

AGPL's distinguishing clause — offering Corresponding Source to users
interacting with the software **remotely over a network** — does not trigger
here: RS-Key is firmware for a local USB authenticator, not a network-facing
service. The operative obligations are the ordinary GPLv3 ones (source,
notices, build/install instructions), all met above.

## GPLv3 §6 "Installation Information" (anti-tivoization): not applicable to this project

GPLv3 §6 (incorporated by AGPLv3) requires "Installation Information" only when
covered software is **conveyed in or with a User Product**. RS-Key's
distribution model does not engage it:

- **RS-Key is not sold as hardware.** It is self-built and self-flashed.
- **Shipped units are not locked to a vendor key.** Secure boot, the OTP master
  key and anti-rollback ([docs/production.md](docs/production.md)) are
  **optional and user-provisioned**: the user fuses **their own** keys, so the
  user always retains the ability to build, sign and install modified firmware.

If RS-Key were ever sold as hardware with secure boot **locked to a
distributor key**, §6 *would* apply and the distributor would have to provide
Installation Information (signing keys or a supported signing path), ship
unlocked, or require buyer-provisioned keys. That scenario is explicitly out of
scope for this project.

## Dependencies

All third-party Rust dependencies are permissive (MIT, Apache-2.0, BSD-*,
Zlib, Unicode-3.0, Unlicense, BlueOak-1.0.0) and AGPL-compatible. There are
**no** GPL/LGPL/EPL/CDDL/SSPL/BUSL/Commons-Clause/proprietary dependencies.
This is enforced on every build by `cargo-deny` (see [deny.toml](deny.toml));
`./scripts/check.sh` fails if a non-allow-listed license appears. Preserve
upstream notices when distributing binaries.

The vendored upstream **test** suites under `third_party/` carry their own
(GPL) per-file headers and are run-only — never compiled into the firmware.
See [third_party/README.md](third_party/README.md).

## Trademark / branding

RS-Key is **not affiliated with or endorsed by** Yubico, Nitrokey or Raspberry
Pi. The **default** USB identity deliberately mimics a YubiKey
(VID `0x1050` / PID `0x0407`, product string and reported firmware version) so
that stock tooling (`ykman`, Yubico Authenticator, udev rules) works — this is
a **local-interoperability convenience only**. Do **not** distribute hardware
carrying that identity or the "YubiKey" name; build presets for neutral
identities (`Pico`, `Dev`, custom VID/PID) exist — see
[docs/build.md](docs/build.md). Comparisons to "YubiKey 5" in the docs are
nominative/comparative use.
