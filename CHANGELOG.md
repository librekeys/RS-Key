<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Changelog

All notable changes to RS-Key are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and **releases** are
versioned with [SemVer](https://semver.org/).

Two other version numbers live in the firmware and are deliberately **not** this
tag: the USB `bcdDevice` build counter (bumped on every behavior change), and
`FW_VERSION` — the YubiKey-compatibility version reported to host tools (5.7.4).

## [Unreleased]

### Added

- **The `rsk` CLI can run without Nix.** A `tools/pyproject.toml` packages the
  CLI so it installs from any Python ≥ 3.9 toolchain —
  `uvx --from ./tools rsk …`, `uv tool install ./tools`, `pipx install ./tools`,
  or plain `pip`. The Nix dev shell stays the primary, pinned path; this mirrors
  its CLI runtime deps (`hidapi`, `cryptography`, `pyscard`, `fido2`,
  `mnemonic`, `shamir-mnemonic`) for hosts without Nix. See
  [tools/README.md](tools/README.md). Host-tool only; no `bcdDevice` bump.

### Changed

- **FIDO2 PIN entry is now uniform across the CLI.** Commands disagreed on how
  to take a PIN: most accepted only `--pin` (and aborted on a PIN-protected
  device when it was omitted), while `fido list-passkeys` and `fido set-pin`
  prompted interactively with no flag at all. Every PIN-gated command (`backup
  export`/`restore`, `audit log`/`verify`, `lock enable`/`disable`, `inventory
  verify`, `fido list-passkeys`/`set-pin`/`attestation import`/`clear`) now
  accepts the PIN **either** way — `--pin` flag **or** an interactive prompt —
  through one chokepoint (`rsk.common.resolve_pin`) that only prompts when the
  device actually has a PIN, so touch-only devices are never asked. Host-tool
  only; no `bcdDevice` bump.
- **The `rsk-tui` cockpit now routes PIN entry through one chokepoint too.** Its
  four per-action PIN steps collapsed into a single `App::gate_pin` +
  `Step::PinThenRun`, so "prompt for the FIDO2 PIN iff the device has one, else
  run" lives in exactly one place (mirroring the CLI's `resolve_pin`). PIN-vs-
  phrase collection in the modal flow is now explicit instead of a catch-all (a
  stray text input can no longer land in the PIN buffer), and the four
  `device requires a PIN` strings were unified. No behaviour change for users;
  host-tool only, no `bcdDevice` bump.

### Security

- **OATH credential secrets are now sealed at rest.** Every other applet
  (FIDO, PIV, OpenPGP, rescue) AES-encrypts its keys before they reach flash;
  OATH alone stored its TOTP/HOTP shared secrets — and the SET CODE key — as
  plaintext TLV. They are now AES-256-GCM-sealed under the device `kbase`
  (`HKDF(serial_hash, kbase, "OATH/KEYS")`), the same device-seal the PIV slot
  keys use. A one-time boot migration re-seals any credential enrolled before
  this release, so existing accounts keep working. With the OTP MKEK burned, an
  extracted flash image no longer reveals OATH secrets. `bcdDevice` `0x0765` →
  `0x0766`.
- **The at-rest seal path is now enforced by types, not convention.** A slot
  that holds a sealed secret is a `KeyFid`, distinct from a plaintext `u16` file
  id, and the only writer that accepts one is `Fs::put_key(KeyFid, Sealed)` —
  where `Sealed` is produced only by a seal routine. A stray
  `fs.put(key_fid, raw_secret)` no longer compiles (asserted by a `compile_fail`
  doctest). This is the chokepoint whose absence let OATH ship its secrets in
  the clear; every applet's key FIDs were moved onto it.
- **Resident-credential RP domains are now boxed at rest.** A discoverable
  credential's `EF_RP` record stored the relying-party id (the site's domain)
  in cleartext, so a flash dump revealed the *list of sites you hold passkeys
  for* — a privacy leak, even though the keys themselves were sealed. The domain
  is now ChaCha20-Poly1305-boxed under the device seed (the same seal the
  credential body uses), with the rpId **hash** kept in cleartext as the O(1)
  lookup key. A boot migration re-boxes records enrolled before this release.
  Honest residual: the rpId hash remains, so a dump can still *dictionary-attack*
  guessable domains — but the plaintext site list is gone. `bcdDevice` `0x0766`
  → `0x0767`.

## [0.2.3] — 2026-06-18

### Changed

- **LED turns green (idle) as soon as the host configures the device**, instead
  of staying on the red boot status until the first applet command arrives. A
  healthy, enumerated key that nothing is talking to yet — e.g. a Linux host with
  no PC/SC daemon running — used to look dead (red) even though it was ready. A
  device-level USB `Handler::configured` callback now flips the status on
  configuration. `bcdDevice` `0x0764` → `0x0765`.

### Fixed

- **~90 s boot stall (LED stuck on the red BOOT status) on some RP2350 boards.**
  `FidoRng::new` seeds the HMAC-DRBG with 48 bytes from the hardware TRNG, and
  the embassy driver runs an autocorrelation health-check on every generated
  block — on a failed check it soft-resets and re-samples in a loop. At the
  default `sample_count` of 25, consecutive ROSC samples on a marginal unit are
  too correlated, so the check failed almost every time and seeding blocked a
  variable 30–105 s on **every** boot (init runs before the USB pull-up, so the
  device was simply absent from the bus that whole time — looked dead, worst on
  strict hosts). Raising `sample_count` to 1000 decorrelates the samples so the
  check passes first try: **~1.5 s boot, HW-verified** on the affected board.
  Entropy quality is unchanged — the NIST health checks stay enabled and the
  source is the same; the seed is just gathered reliably. `bcdDevice` `0x0763`
  → `0x0764`.

- **PIV tab *still* slow after the present-cache fix below: `GET METADATA` over
  empty key slots.** That bitmap guarded `read` and `size`, but `has_data` — a
  third absent-probe method — still called the backend directly, so a missing
  FID scanned the whole partition. PIV `GET METADATA` checks `has_data(slot)`
  first, and `ykman piv info` / Yubico Authenticator's PIV tab read metadata for
  ~24 mostly-empty slots (`9A/9C/9D/9E` + 20 retired), so each tab switch paid
  ~24 full scans ≈ 4 s of green-blinking even though every individual APDU
  answered in ~30 ms. `has_data` now consults the same bitmap → `O(1)` for an
  absent slot; measured `ykman piv info` **4.16 s → 0.26 s** (~16×) on hardware.
  `bcdDevice` `0x0762` → `0x0763`.

- **Slow applet listing (PIV especially), seen as long green-blinking when
  switching tabs in Yubico Authenticator.** A backend `read`/`size` of an
  *absent* file scanned the entire ~1.4 MB KV partition to confirm absence, so
  enumerating a sparse object range was `O(slots · flash)` — opening the
  Certificates tab probes ~25 mostly-empty PIV certificate slots, each a full
  scan. (OATH had the same class of bug, fixed earlier; PIV/others did not.) The
  filesystem now keeps a fixed present/absent bitmap of all FIDs (rebuilt on
  boot, maintained on every write/remove), so an absent `read`/`size` returns
  without touching the backend — `O(1)` instead of a full scan. `bcdDevice`
  `0x0761` → `0x0762`.

- **USB enumeration race at boot (first field report).** On a Waveshare RP2350
  the device would "blink red and not be recognised," recovering only after
  several replugs. `builder.build()` asserts the bus pull-up, so the host begins
  enumerating the moment the device attaches — but the task that answers control
  transfers (`usb_task`) was spawned only after a block of per-boot init (seed +
  attestation cert + OpenPGP DEK + flash writes, heaviest on a fresh device). The
  host enumerated into an attached-but-mute device and timed out the first
  descriptor request; a lenient host (macOS) usually won, a strict one often did
  not. Boot now completes all that init **before** attaching, and spawns
  `usb_task` immediately after `build()`, so enumeration is serviced with no
  blocking gap. `bcdDevice` `0x0760` → `0x0761`.

## [0.2.2] — 2026-06-15

No firmware change — `bcdDevice` stays `0x0760` and the eight `.uf2` images are
bit-identical to 0.2.0. This release ships the fixed, hardened release pipeline:
0.2.0 published its GitHub Release without provenance, because the SLSA
generator's "append the provenance to the release" model is incompatible with
GitHub's immutable releases (the late asset upload is rejected — even on a draft).

### Changed

- Build provenance now uses GitHub's native `attest-build-provenance`, generated
  from inside a **reusable workflow** (`release-build.yml`). Running the build
  and the attestation in an isolated, identity-bound reusable workflow raises the
  release to **SLSA v1 Build Level 3** (an inline attestation step alone is only
  Build L2). Each `.uf2` is attested keyless (Sigstore/Fulcio + the Rekor log)
  into the **attestation API** instead of being uploaded as a release asset, so
  it stays compatible with immutable releases. Verify with
  `gh attestation verify --signer-workflow …` (`docs/supply-chain.md`).
- All GitHub Actions bumped to their current major versions (off the deprecated
  Node 20 runtime).

## [0.2.0] — 2026-06-15

The cycle since 0.1.0. USB `bcdDevice` is now `0x0760` (incremented once per
firmware change along the way).

### Added

- **Own AAGUID + FIDO Metadata Statement.** The authenticator reports its own
  model identity (`2479c7bf-6b30-5683-9ec8-0e8171a918b7`, a reproducible UUIDv5)
  instead of the inherited pico-fido one, and ships a self-published FIDO
  Metadata Statement (`metadata/rs-key.metadata.json`) with a drift guard.
- **Supply-chain provenance.** Releases now carry SLSA build provenance
  (slsa-github-generator, keyless) and pass a release-time reproducibility gate
  that rebuilds all eight flavors bit-identical before anything is published.
- **Dependency review.** A `cargo-vet` gate (Mozilla / Google / ISRG / Zcash
  audits + recorded exemptions) blocks new unreviewed crates; a new
  `docs/supply-chain.md` documents the whole chain.
- **Versioned documentation site** — `main`, `develop` and tagged versions are
  published side by side with a switcher.
- **Kani proofs** that the OpenPGP import (BER) parser is panic-free and
  terminating, plus a CI guard that `flake.lock` stays in sync with `flake.nix`.

### Changed

- Every GitHub Action is pinned to a commit SHA, kept fresh by Dependabot.
- The physical-attack posture docs are reframed around the published RP2350
  hacking challenges (threat model / OTP fuses / limitations).

### Fixed

- **U2F routing.** A vendor-AID SELECT over CTAPHID_MSG no longer leaves a sticky
  applet selection that routed later U2F REGISTER / AUTHENTICATE / VERSION into
  `0x6D00`; the MSG selection is dropped on every CTAPHID_INIT.
- **OATH performance.** RESET / LIST / CALCULATE-ALL / lookup probed all 255
  credential slots, and each absent slot rescanned flash; they now touch only
  present credentials — OATH RESET dropped from ~39 s to ~0.5 s.
- **USB transport wedge.** Bounding the CTAPHID/CCID IN-endpoint writes stops an
  abandoned transaction from wedging the interface until a replug.
- The OpenPGP card-status self-test now follows GET DATA response chaining.

### Security

- **Constant-time audit fixes** — RSA base blinding on the raw path and
  constant-time OTP access-code comparisons (`docs/ct-audit.md`).
- **Fault-injection fences** on the PIN and secure-boot gates, so a glitched
  single comparison can't skip the check.

## [0.1.0] — 2026-06-13

First public release — an open-source security-key firmware for the Raspberry Pi
RP2350 (Cortex-M33), a behavioral reimplementation of the AGPL-3.0 pico-keys
family that keeps the "enterprise" features in the open tree.

### Security keys / protocols

- **FIDO2 / WebAuthn / U2F** — passkeys (discoverable credentials), second-factor,
  `ssh -t ed25519-sk`, hmac-secret and largeBlobs; user presence gated on the
  BOOTSEL button (the default touch build).
- **OpenPGP card 3.4** — sign / decrypt / authenticate; EC (Ed25519, NIST, brainpool)
  and on-card RSA keygen (2048/3072/4096) accelerated across both cores.
- **PIV** — X.509 slots, attestation, the Yubico management extensions; works
  through PKCS#11 / OpenSC and the OS-native stacks.
- **OATH (YKOATH)** — TOTP / HOTP credential store.
- **Yubico OTP** — slot programming and challenge-response over CCID, plus the
  HID-keyboard typing path.

### Enterprise features, in the open tree

- forceChangePin enforcement, a SHA-256-chained signed audit trail, an opt-in
  `fips-profile`, organizational attestation (import key + chain), and host-side
  fleet inventory / verification / offboarding tooling.

### Hardening

- Secure boot + anti-rollback (RP2350 OTP), keys sealed under an OTP-burned
  device root, and an at-rest soft-lock of the FIDO seed.

### Tooling

- The `rsk` CLI and the `rsk-tui` ratatui dashboard; guided primary + backup
  device pairing; secure-boot key-rotation tooling. Run without the dev shell via
  `nix run .#rsk`, `.#rsk-tui`, and a one-command flasher `.#flash`.

### USB identity

- The default build presents this project's **own** pid.codes identity
  (`0x1209:0x0001`, "RS-Key Security Key") — not a YubiKey masquerade. An opt-in
  `VIDPID=Yubikey5` flavor borrows the YubiKey identity for `ykman` / Yubico
  Authenticator interop.

### Assurance

- 39 fuzz targets, Kani proofs, a Miri pass, power-cut torture, bit-reproducible
  `nix build` images (per platform, per `flake.lock`), and a hardware-verified
  interop matrix ([docs/interop.md](docs/interop.md)).

### Release artifacts

- Eight firmware flavors (`up-button` × `advertise-pqc` × `fips-profile`), each a
  reproducible **unsigned** `.uf2` — on a secure-boot device, seal it with your
  own key before flashing (`nix run .#flash`, or see
  [docs/production.md](docs/production.md)).
- `SHA256SUMS` over every artifact, a keyless [cosign](https://docs.sigstore.dev/)
  signature of it, and a CycloneDX SBOM. See
  [docs/releases.md](docs/releases.md) to verify a download.

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TheMaxMur/RS-Key/releases/tag/v0.1.0
