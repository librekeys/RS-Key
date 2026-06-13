# Interop — does it actually work with the real tools?

RS-Key has three test layers below this one (`tests/`, the vendored
[`third_party/`](../third_party/README.md) suites, and the host `cargo test`
/ fuzz / Kani stack — see [testing.md](testing.md)). All of them drive the
device at the **protocol** level: APDUs, CBOR, CTAPHID frames. They prove the
wire format is correct against *our* reading of the specs and against two
upstream suites.

This document is the layer above: **does the device work end-to-end with the
software a real user actually runs** — `gpg`, `ssh`, a browser's WebAuthn
stack, `ykman`, `fido2-token`, OpenSC — not with our own scripts. Protocol
conformance is necessary but not sufficient: a response can be spec-arguable
yet still trip a strict third-party parser. (The canonical example is the
`ykman openpgp info` crash below: our GET DATA `6E` was readable by `gpg` but
rejected by ykman's stricter `Tlv.unpack(0x6E, …)`.)

The matrix is a living artifact. A cell is **evidence** only once it has been
run on hardware and dated; everything else is `⏳ untested`. The `0758` /
`0759` tags in the Status column are the firmware `bcdDevice` the cell was run
against.

**Baseline — 2026-06-13, firmware `0x0758`** (`tests/interop/run.py`, live
device): libfido2 enumeration + getInfo, `gpg --card-status`, and `ykman`
`piv`/`oath`/`otp` info all ✅; `ykman openpgp info` ❌ (the GET DATA `6E`
wrapper bug below — reproduced live as `ERROR: Incorrect TLV length`).

**Re-verified — 2026-06-13, firmware `0x0759`** (the fix): the full CLI sweep
is green — **7 passed, 0 failed**, `ssh-sk` skipped (touch). `ykman openpgp
info` now prints the card (`OpenPGP version: 3.4`, app `4.6.0`, PIN counters)
instead of the TLV error.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | verified end-to-end on hardware (date + firmware in Notes) |
| ⚠️ | works with caveats / partial coverage |
| ❌ | broken — known defect (link the issue/fix) |
| ⏳ | not yet run on hardware |
| 🚫 | not applicable on this platform / not implemented |

## A note on firmware builds

The CLI suites cannot press the BOOTSEL button, so anything touch-gated either
needs the **no-touch test build** (`cargo build -p firmware
--no-default-features`, see [build.md](build.md)) or a human. The matrix splits
accordingly:

- **CLI sweep** — run on the **no-touch** build; fully automatable
  (`tests/interop/run.py`).
- **GUI / ceremony** — run on the **touch** build with a finger on the button
  (browser WebAuthn, `ssh-keygen -t ed25519-sk`, OpenPGP UIF signing).

## Matrix

### FIDO2 / WebAuthn / U2F

| Consumer | What it exercises | Build | How | Status |
|---|---|---|---|---|
| `fido2-token -L` / `-I` (libfido2) | enumeration + getInfo | no-touch | `tests/interop/run.py` | ✅ `0759` |
| `fido2-cred` / `fido2-assert` (libfido2) | make credential / get assertion | touch | `tests/interop/run.py --touch` | ⏳ |
| python-fido2 (Yubico) | full CTAP2 flows | no-touch | `pytest third_party/pico-fido-tests/pico-fido` | ⏳ |
| Chrome WebAuthn | register + authenticate | touch | [webauthn.io](https://webauthn.io) (manual) | ⏳ |
| Firefox WebAuthn | register + authenticate | touch | [webauthn.io](https://webauthn.io) (manual) | ⏳ |
| Safari WebAuthn | register + authenticate | touch | [webauthn.io](https://webauthn.io) (manual) | ⏳ |
| `ssh-keygen -t ed25519-sk` + `ssh` | sk-key enrol + auth | touch | manual | ⏳ |

### OpenPGP card

| Consumer | What it exercises | Build | How | Status |
|---|---|---|---|---|
| `gpg --card-status` | application-related-data read | either | `tests/interop/run.py` | ✅ `0759` |
| `gpg --edit-card` keygen/sign/encrypt | full card lifecycle | touch (UIF) | manual | ⏳ |
| `ykman openpgp info` | `Tlv.unpack(0x6E, …)` strict parse | either | `tests/interop/run.py` | ✅ `0759` (was ❌ on `0758`) |
| openpgp-card-tests (Gnuk-derived) | spec suite | no-touch | `pytest third_party/openpgp-card-tests/…` | ⏳ |

### PIV

| Consumer | What it exercises | Build | How | Status |
|---|---|---|---|---|
| `ykman piv info` | discovery + slot state | no-touch | `tests/interop/run.py` | ✅ `0759` |
| OpenSC `pkcs11-tool` | PKCS#11 module load + sign | no-touch | needs `brew install opensc` | ⏳ |
| macOS native (`sc_auth`, Keychain) | system smartcard | no-touch | manual | ⏳ |

### OATH / OTP

| Consumer | What it exercises | Build | How | Status |
|---|---|---|---|---|
| `ykman oath accounts list` | OATH credential listing | no-touch | `tests/interop/run.py` | ✅ `0759` |
| Yubico Authenticator (app) | TOTP/HOTP GUI | no-touch | manual | ⏳ |
| `ykman otp info` | OTP slot state | no-touch | `tests/interop/run.py` | ✅ `0759` |
| OTP keyboard (types the code) | USB-HID keyboard emulation | touch | manual (focus a text field) | ⏳ |

## Known issues

### `ykman openpgp info` rejected our GET DATA `6E` — FIXED (`0x0759`)

ykman/yubikit parse the application-related-data response with
`ApplicationRelatedData.parse`, which calls
`Tlv.unpack(0x6E, response)` — it requires the whole GET DATA `6E` reply to be
a single TLV tagged `6E`. RS-Key stripped the outer `6E 82 LL LL` wrapper for
*every* non-flash DO, returning the bare nested `4F …`, so ykman failed with
`ERROR: Incorrect TLV length` (the `4F` TLV parses but leaves a trailing
remainder `Tlv.unpack` rejects) while `gpg` (which tolerates either form)
worked. Fixed by keeping
the wrapper on **constructed** template DOs (`6E/65/73/7A/FA`, BER constructed
bit `0x20`) and stripping only **primitive** DOs — which is what real OpenPGP
cards do. See `crates/rsk-openpgp/src/getdata.rs`. **Verified on hardware
2026-06-13 (firmware `0x0759`):** `ykman openpgp info` prints the card data
(`OpenPGP version: 3.4`, app `4.6.0`, PIN counters) instead of `ERROR:
Incorrect TLV length`.

```sh
ykman openpgp info     # prints card data, no TLV traceback
```

## How to run the CLI sweep

```sh
# Flash the no-touch build first (signed, if secure boot is on).
nix develop -c python tests/interop/run.py            # automatable cells only
nix develop -c python tests/interop/run.py --touch    # also the touch cells (presses needed)
nix develop -c python tests/interop/run.py --json      # machine-readable
```

The runner discovers the device via `fido2-token -L` (HID) and `ykman info`
(CCID), runs each probe, and prints this matrix's automatable rows with live
results. It never mutates state by default (read-only probes); destructive
cells (enrol/keygen) are opt-in.
