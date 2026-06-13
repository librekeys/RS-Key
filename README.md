# RS-Key

[![ci](https://github.com/TheMaxMur/RS-Key/actions/workflows/ci.yml/badge.svg)](https://github.com/TheMaxMur/RS-Key/actions/workflows/ci.yml)
[![deep-checks](https://github.com/TheMaxMur/RS-Key/actions/workflows/deep-checks.yml/badge.svg)](https://github.com/TheMaxMur/RS-Key/actions/workflows/deep-checks.yml)

**RS-Key** (**RSK**, *Raspberry Security Key* — also a pun on "written in Rust")
is an open-source security-key firmware for the Raspberry Pi **RP2350**. It
turns a $5–15 RP2350 board into a USB authenticator that speaks the same
protocols as a commercial YubiKey or Nitrokey:

- **FIDO2 / WebAuthn / U2F** — passkeys, two-factor login, `ssh ed25519-sk`
- **OpenPGP card 3.4** — `gpg` signing, encryption, authentication
- **PIV** — X.509 smart-card (`ykman piv`, PKCS#11)
- **OATH** — TOTP/HOTP authenticator codes (`ykman oath`, Yubico Authenticator)
- **Yubico OTP** — including an emulated USB keyboard that types the OTP
- **Post-quantum FIDO2** — ML-DSA-44 (FIPS 204) credentials, today
- **Wallet-style seed backup** — BIP-39 / SLIP-39 Shamir shares
- **At-rest soft-lock** — the FIDO seed leaves flash encrypted to a key only
  you hold
- **Signed audit trail** — a tamper-evident on-device event journal,
  checkpointed by the OTP attestation key (`rsk audit verify`)
- **Enterprise attestation** — CTAP 2.1 EA with an org-provisioned
  attestation key/chain (`rsk fido attestation import`)
- **Silicon root of trust** — OTP-fused master key + RP2350 secure boot

It is written in pure Rust (`no_std`, [embassy](https://embassy.dev/)) with two
audited exceptions, fuzzed on every parser, and tested against the upstream
python-fido2 and OpenPGP card test suites.

> ⚠️ **EXPERIMENTAL.** RS-Key is a hobby project. It has not been audited, the
> hardware has no secure element, and you should not guard secrets you cannot
> afford to lose (or have stolen) with it. See the
> [threat model](docs/threat-model.md) and [limitations](docs/limitations.md)
> before trusting it with anything real.

RS-Key is a from-scratch Rust reimplementation of
[pico-keys](https://github.com/polhenarejos) (pico-fido / pico-openpgp /
pico-keys-sdk) by Pol Henarejos, licensed — like upstream —
under **AGPL-3.0-only**. See [NOTICE](NOTICE).

## Hardware

Any RP2350 board with USB. Developed and tested on the **Waveshare
RP2350-One** (the WS2812 status LED on GPIO16 works out of the box; other
boards run fine without the LED). The RP2350's dual Cortex-M33, 520 KB SRAM,
TRNG, OTP fuses and glitch detectors do all the work — there is no secure
element and no debugger requirement: everything flashes over USB BOOTSEL.

The defaults target a 4 MB chip with the LED on GPIO16; a different flash size
or LED pin is a build knob (`FLASH_SIZE`, `LED_PIN` — see
[docs/build.md](docs/build.md)), so most RP2350A boards work with at most a
one-line change. A standard 12 MHz crystal is assumed.

## Quick start

```sh
git clone <this repo> && cd rs-key
nix develop                      # toolchain, picotool, host tools — everything

cargo build --release -p firmware
picotool uf2 convert target/thumbv8m.main-none-eabihf/release/firmware -t elf firmware.uf2

# hold BOOTSEL, plug the board in, then:
cp firmware.uf2 /Volumes/RP2350/         # macOS; on Linux: the RP2350 mass-storage mount
```

Re-plug, and the board enumerates as a YubiKey-compatible composite device.
Enroll a passkey in any browser, or an SSH key:

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk   # 2 touches (+ PIN if set)
ssh-copy-id -i ~/.ssh/id_ed25519_sk you@host
ssh -i ~/.ssh/id_ed25519_sk you@host               # logs in with one touch
```

The default build requires a **physical touch** (the BOOTSEL button) for FIDO
operations — like a real key. Build with `--no-default-features` for a
no-touch test build (the automated test suites need it).

Full walkthrough: [docs/quickstart.md](docs/quickstart.md) ·
Linux host setup (pcscd/udev/polkit): [docs/linux.md](docs/linux.md)

## Two ways to run it

| | Dev (default) | Production-ish (opt-in, **experimental**) |
|---|---|---|
| Flash | drag-and-drop UF2 | UF2 **signed** with your key (`picotool seal`) |
| Master-key root | flash-derived | **OTP-fused MKEK**, BOOTSEL-unreadable |
| Boot | any image | **secure boot** — only your signed images |
| Set up by | nothing to do | [docs/production.md](docs/production.md) |

The production path burns **irreversible** RP2350 fuses, changes your reflash
workflow forever (signed images only) and can brick the board if you skip
steps. It is also what makes a stolen board's flash dump worthless. Read
[docs/production.md](docs/production.md) end to end first.

## Capacity

Everything is stored in the RP2350's flash, so limits are generous:

| | **RS-Key** | YubiKey 5 (fw 5.7) |
|---|---|---|
| Resident passkeys | **256** | 100 (25 before 5.7) |
| OATH accounts | **255** | 64 (32 before 5.7) |
| PIV key slots | 24 + attestation | 24 + attestation |
| OpenPGP keys | 3 (SIG/DEC/AUT) | 3 + attestation |
| OTP slots | **4** (2 Yubico-compatible + 2 extra) | 2 |
| FIDO credBlob / largeBlob | 128 B / 2048 B | 32 B / 4096 B |
| ML-DSA-44 (PQC) credentials | **yes** (COSE −48) | no |

Non-resident credentials (the usual `ssh-sk` and 2FA kind) are derived from
the master seed and are effectively unlimited.

## Host tools

The dev shell puts three tools on `PATH`:

- **`rsk`** — the device CLI: `rsk status`, `rsk backup`, `rsk lock`,
  `rsk secure-boot`, `rsk otp`, `rsk fido`, `rsk led`, `rsk reboot`, …
- **`rsk-tui`** — a live terminal dashboard (device state, backup, LED)
- **`rsk-wipe`** — a RAM-only flash wiper for clean-slate testing

## Documentation

| | |
|---|---|
| [Quick start](docs/quickstart.md) | flash, enroll, first login |
| [Build options](docs/build.md) | every flag: VID/PID presets, firmware version, touch, PQC, … |
| [Production setup](docs/production.md) | signed boot + OTP fuses, step by step (**irreversible**) |
| [Feature guides](docs/guides/) | FIDO2, SSH, OpenPGP, PIV, OATH, OTP slots, backup, soft-lock, LED, audit, attestation, fleet |
| [Threat model](docs/threat-model.md) | what it protects against, and what it does not |
| [Architecture](docs/architecture.md) | crates, executors, flash layout |
| [Limitations](docs/limitations.md) | what is not covered, and why |
| [`unsafe` audit](docs/unsafe.md) | every unsafe site, justified |
| [Testing](docs/testing.md) | host tests, fuzzing, on-device suites |
| [Interop](docs/interop.md) | does it work with real `gpg`/`ssh`/browsers/`ykman` — the matrix |
| [Linux setup](docs/linux.md) | pcscd, udev, polkit, scdaemon |
| [Motivation](docs/motivation.md) | why this exists |
| [Contributing](CONTRIBUTING.md) | setup, the merge gate, code rules, how PRs land |
| [Security policy](SECURITY.md) | how to report vulnerabilities (privately) |

## Limitations (the honest short list)

- **No secure element.** The RP2350 + OTP + secure boot is a real hardening
  story, but physical attacks (decap, fault injection beyond the glitch
  detectors, flash-emulation TOCTOU on the XIP image) are out of scope.
- **Seed backup covers the deterministic identity only** — resident passkeys,
  OpenPGP and PIV keys do not survive a board swap.
- **No Brainpool / X448 / Ed448** OpenPGP curves (no production-grade
  `no_std` Rust implementations).
- The default USB identity **masquerades as a YubiKey** for tool
  compatibility; don't distribute devices with those IDs.

Details and reasoning: [docs/limitations.md](docs/limitations.md).

## License

**AGPL-3.0-only** — see [LICENSE](LICENSE) and [NOTICE](NOTICE). RS-Key is a
derivative of AGPL-licensed pico-keys; it stays AGPL, and so must forks.
Not affiliated with or endorsed by Yubico, Nitrokey or Raspberry Pi.
