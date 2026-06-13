<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# rsk-tui — the terminal cockpit

`rsk-tui` is a host-side dashboard for an RS-Key. It talks to the device
directly — CTAPHID over hidapi and the CCID applets over PC/SC — so it does not
shell out to `rsk` or any other process. It lives in its own workspace
(`tools/tui`), separate from the firmware, and links the host PC/SC and HID
stacks.

It is a companion to the `rsk` CLI, not a replacement: the cockpit covers the
safe, day-to-day reads and a few in-band actions (LED, seed backup, reboot,
audit, identity verify). Irreversible production rituals — secure-boot staging,
OTP fuses, factory resets, soft-lock, attestation import — stay in the CLI on
purpose, and the cockpit points you at the exact command instead of doing them.

```mermaid
flowchart LR
    tui["rsk-tui (host process)"] -->|hidapi / CTAPHID| fido["Device — FIDO"]
    tui -->|PC/SC / pcscd| ccid["Device — CCID applets<br/>OpenPGP · PIV · OATH · OTP"]
```

## Running it

In the dev shell `rsk-tui` is on `PATH`:

```sh
nix develop
rsk-tui              # interactive cockpit
```

Without Nix, run it from its workspace (the repo defaults to the firmware
target, so name the host target explicitly — this is what the launcher does):

```sh
cargo run --release --manifest-path tools/tui/Cargo.toml \
  --target "$(rustc -vV | sed -n 's/host: //p')"
```

On Linux the CCID half needs `pcscd` + a polkit rule; see
[linux.md](../linux.md). FIDO works as soon as the udev rules are in place.

### Flags

| Flag            | Effect                                                          |
|-----------------|----------------------------------------------------------------|
| *(none)*        | interactive cockpit                                            |
| `--demo`, `--mock` | interactive cockpit against a **simulated** device — no hardware needed |
| `--once`        | print the gathered status once (human-readable) and exit       |
| `--json`        | one-shot machine-readable status (JSON) and exit               |
| `--selftest`    | native backup export/restore round-trip (needs a no-touch build) |
| `-h`, `--help`  | usage                                                          |

`--demo` is handy for screenshots, docs, and trying the navigation without a
key plugged in. Demo data is clearly labelled `[DEMO]` and every simulated
action is prefixed `[demo]`; it never pretends to touch hardware.

A non-interactive snapshot of the simulated device (`rsk-tui --once --demo`)
gives a sense of what the cockpit reads:

```text
[DEMO — simulated device]
device     : serial 37bebfdca282 · fw 5.7.4 · bcd 0x0759
transports : HID present  PC/SC present  CCID present
serial     : 37bebfdca282523b
firmware   : 5.7.4  bcdDevice 0x0759  sdk 3.4
fido       : U2F_V2, FIDO_2_0, FIDO_2_1  clientPin=true
backup     : sealed=false  has_seed=true
seed lock  : off
secure boot: ENABLED  (enabled=true locked=false bootkey=0x1)
rollback   : not required  boot version 0/48
org attest : not installed
applets    : OpenPGP present  PIV present  OATH present  OTP present
```

<!-- TODO(docs): a screenshot of the interactive cockpit could live in docs/assets/,
     but rsk-tui --demo is a full-screen TUI and can't be rendered headlessly here.
     Capture it manually with `rsk-tui --demo` rather than committing a fabricated
     image. The ASCII layout below and the --once snapshot above are honest stand-ins. -->

## Layout

```
┌ header: app · health · device identity · refreshed ─────────────┐
│ sections │ selected section: status fields + action menu        │
│  …       │                                                      │
├──────────┴──────────────────────────────────────────────────────┤
│ events: recent operations and errors                            │
├─────────────────────────────────────────────────────────────────┤
│ last result · key bindings                                      │
└─────────────────────────────────────────────────────────────────┘
```

The sidebar narrows and the event panel drops away on small terminals; the UI
keeps working down to a few rows. Status uses an `OK / WARN / ERROR / UNKNOWN`
word plus a colored glyph, so it reads on a monochrome or color-blind terminal.
Set `RSK_TUI_ASCII=1` (or run in a non-UTF-8 locale) to force ASCII glyphs.

## Key bindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift-Tab`, `←` / `→` | switch section |
| `↑` `↓` or `j` `k` | move selection in the action list |
| `Enter` | run the selected action |
| `r` | refresh device status |
| `/` | search actions across all sections |
| `?` | jump to Help |
| `Esc` | cancel a modal / input |
| `q` or `Ctrl-C` | quit (terminal restored on exit) |

The status also auto-refreshes every few seconds while you are not in a modal.

## Sections and what they do

| Section | Reads (safe) | In-band actions |
|---------|--------------|-----------------|
| Overview | identity (serial, fw, bcdDevice, sdk, aaguid), transports, backup/lock/secure-boot/rollback/attestation/flash | Refresh, Verify identity |
| FIDO | CTAPHID presence, versions, clientPIN, options | — |
| OpenPGP | applet presence | — |
| PIV | applet presence | — |
| OATH / OTP | applet presence | — |
| Backup | seed / sealed / lock state | Export, Restore, Finalize (BIP-39) |
| LED | — | Read state, Cycle idle color |
| Audit | journal + checkpoint key hint | Read journal, Verify identity |
| Reboot | device summary | Reboot → app, Reboot → BOOTSEL |
| Help | key bindings, section guide, safety model | — |

**Verify identity** issues a fresh challenge, has the device sign it with its
DEVK-derived P-256 attestation key (vendor `AUDIT_CHECKPOINT`), and **verifies
the ECDSA signature locally** — it is a real cryptographic check, not a display
of device-asserted bytes. It needs a touch, a PIN if one is set, and a
provisioned OTP DEVK (otherwise it says so).

### CLI-only / unsupported in the TUI

These are surfaced as menu entries that, when selected, print the exact command
to run — they are never performed from the cockpit:

- **FIDO**: set/change PIN, list resident passkeys, factory reset
- **OpenPGP / PIV / OATH / OTP**: full card data and factory resets (`gpg
  --card-status`, `ykman …`, `rsk openpgp reset`, …)
- **Backup**: SLIP-39 (Shamir T-of-N) export/restore
- **Maintenance** (Reboot section): seed soft-lock, org-attestation import/clear,
  secure-boot staging, OTP fuses — see [production.md](../production.md)

Credential counts are not shown because there is no unauthenticated way to read
them; use `rsk fido list-passkeys --pin …`.

## Safety model — what is and is not logged

- **Destructive or irreversible operations require a typed confirmation**, not a
  single keypress: export (`EXPORT`), restore (`RESTORE`), finalize/seal
  (`SEAL`), reboot to BOOTSEL (`BOOTSEL`). Reboot to app uses a yes/no prompt.
- **PINs are masked** on entry and **never written to the event log**. The log
  additionally redacts any live PIN/phrase substring as a backstop.
- **The seed is shown only after you confirm export.** It appears once, in a
  modal, is zeroized from memory when you press a key, and **never reaches the
  event log or any file**. The same goes for a restore phrase you type in.
- Sensitive buffers (PIN, phrase, revealed seed) are wiped (`zeroize`) on cancel,
  on submit, and on Ctrl-C.
- The terminal is restored on every exit path — `q`, `Ctrl-C`, an I/O error, or
  a panic.

## Architecture (for contributors)

`tools/tui/src` is split so rendering, state, and I/O stay separate and the UI
is testable without hardware:

- `model.rs` — typed state (`DeviceSnapshot`, `TransportStatus`, `Section`,
  `Action`, `ActionResult`, `EventLog`, …) and `--json` serialization. No I/O.
- `device.rs` — native CTAPHID + PC/SC I/O behind a `DeviceProvider` trait, with
  `HardwareProvider` (real) and `MockProvider` (`--demo`).
- `app.rs` — app state, navigation, and the modal/confirmation flow.
- `actions.rs` — action dispatch + result handling (the one place that blocks on
  device I/O).
- `input.rs` — key handling → state change + `Flow`.
- `ui.rs` — rendering only.
- `theme.rs` — styles, colors, ASCII fallback.

Because the UI is driven by a `DeviceProvider`, the whole cockpit — navigation,
confirmation flows, secret redaction, rendering — is unit-tested against the
mock with no device attached.

```sh
# fmt / clippy / test / build, host target (the merge gate runs these too):
H="$(rustc -vV | sed -n 's/host: //p')"
cargo fmt   --manifest-path tools/tui/Cargo.toml --check
cargo clippy --manifest-path tools/tui/Cargo.toml --target "$H" --all-targets -- -D warnings
cargo test   --manifest-path tools/tui/Cargo.toml --target "$H"
cargo build --release --manifest-path tools/tui/Cargo.toml --target "$H"
```
