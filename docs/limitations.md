# Limitations — what RS-Key does not do, and why

Honest accounting of the gaps, each with its reasoning. "Not yet" and "never"
are marked.

## Cryptography

- **Brainpool curves (OpenPGP)** — not offered. There is no production-grade
  `no_std` Rust implementation of brainpoolP256/384/512r1; the existing
  crates are experimental. The applet does not advertise the curves, so
  clients never select them. *Status: until a serious crate exists.*
- **X448 / Ed448 (OpenPGP)** — not offered, same reason: RustCrypto coverage
  of Curve448 is thin and unaudited. Cv25519/Ed25519 plus the NIST curves and
  secp256k1 cover practical use. *Status: until a serious crate exists.*
- **RSA-3072/4096 on-card generation is slow** — the prime search dominates,
  and the search cost is the *rejection* of hundreds of composite candidates,
  each one asm-modexp-bound. That is already on both cores with the modexp hot
  path in SRAM ([architecture](architecture.md)): RSA-2048 ~8.9 s → ~4–6 s,
  RSA-3072 ~35 s → ~22 s, RSA-4096 ~65 s → ~50 s, all dominated by how many
  candidates the draw happens to need (the per-keygen spread is wide — 17 s to
  124 s seen at 4096 — because that count is random, not because the silicon
  varies). Per candidate the throughput is ~6.9 ms across both cores. The
  Baillie-PSW that confirms a *survivor* is split between an asm strong
  Miller-Rabin and a software Lucas test, but survivors are only a handful per
  keygen, so neither half moves the total — the lever is fewer candidates
  reaching the modexp, i.e. a deeper small-prime sieve. How deep is set by the
  measured cost ratio: one strong-MR modexp is ~35 ms (1024-bit) / ~239 ms
  (2048-bit) against ~11 µs / ~23 µs for one trial division, so it pays to
  sieve by every prime up to ~3.1k / ~10.5k — far past the old flat
  256-prime (≤1619) sieve. The sieve depth now scales with key size
  accordingly (448 primes at RSA-2048 … 1280 at RSA-4096). Confirmed by an
  A/B on the same device (per-candidate cost, which divides out the
  prime-search-luck variance): **RSA-2048 7.84 → 6.82 ms/candidate (−13%),
  RSA-4096 36.0 → 23.5 ms/candidate (−35%)** against the old flat sieve. The
  device streams keepalives throughout, so tools wait it out; import is fast.
  *Status: inherent to the hardware class; the parallel-scan share is at the
  two-core limit, the sieve depth at the measured modexp:division ratio.*
- **ML-KEM is scaffolding** — compiled, tested, unused: no CTAP PIN/UV
  protocol number for PQC key agreement exists yet to implement.
  *Status: waiting on standards.*
- **PQC interop is ahead of the ecosystem** — ML-DSA-44 credentials work and
  verify, but no browser or mainstream WebAuthn library consumes COSE −48
  against security keys yet, and released Firefox versions abort getInfo if
  the algorithm is *advertised* (hence the `advertise-pqc` build flag,
  default off — capability stays on regardless).

## Backup & migration

- **The seed backup covers the deterministic identity only.** Non-resident
  credentials (`ssh ed25519-sk`, most 2FA registrations) derive from the
  master seed and survive a restore onto a new board. **Not covered:**
  resident passkeys (stored records, not derivable), OpenPGP private keys,
  PIV private keys, OATH secrets, OTP slots — all sealed to the source
  chip. A board swap means re-enrolling those. *Status: by design; a full
  at-rest export would gut the at-rest story.*
- **A finalized backup window stays closed** until a factory reset
  regenerates the seed — lost words cannot be re-exported. Pick a generous
  SLIP-39 share count. *Status: by design (anti-exfiltration gate).*

## Hardware / physical

- **No secure element.** The RP2350's OTP fuses, glitch detectors and secure
  boot are real, but decap, microprobing, advanced fault injection and
  power/EM side channels are out of scope. *Status: never — wrong silicon
  class.*
- **XIP TOCTOU residual** — secure boot verifies the image in external QSPI
  flash, then executes from it; lab hardware emulating the flash chip can
  swap contents between check and execution (the ~1.7 MB image cannot be
  copied to the 520 KB SRAM to run verified-in-place). *Status: never on this
  board; same class as decap.*
- **No TrustZone-M secure/non-secure split.** Considered and rejected: the
  embassy ecosystem has no TrustZone support, so it would mean hand-rolling
  SAU/IDAU configuration, NSC veneers and dual images — the project's
  single biggest item — to defend mainly against parser memory corruption,
  which safe Rust plus fuzzing already address. Physical attacks are
  orthogonal to TrustZone. *Status: revisit only with ecosystem support.*
- **Anti-rollback is opt-in and epoch-coarse** — `picotool seal --rollback`
  plus the `ROLLBACK_REQUIRED` fuse
  ([production.md](production.md#stage-3--anti-rollback-optional)). The OTP
  thermometer has 48 steps for the board's life, so epochs are burned for
  security-relevant releases only, and until the fuse is set any
  previously-signed image still boots. *Status: shipped (optional stage 3).*
- **No image encryption** — pointless for open-source code (no secrets in
  the image; secrets live sealed in flash), and the RP2350 has no
  transparent XIP decryption anyway. *Status: never.*

## Protocol / compatibility

- **The default USB identity is a YubiKey masquerade** (`0x1050:0x0407`,
  reader name `Yubico YubiKey RSK …`, reported firmware 5.7.4). This is what
  makes `ykman`, Yubico Authenticator and stock udev rules work, and it is
  strictly a local convenience: distributing hardware with Yubico's
  identifiers is not OK. Build presets exist for other identities
  ([build.md](build.md)), but third-party vendor tools then stop working —
  they gate on their own VID/PID.
- **OpenPGP secure messaging** is not implemented (rarely used by clients;
  PINs gate everything in practice).
- **One physical button.** Touch = the BOOTSEL button; there is no
  fingerprint, no display, and "number matching" style UV is impossible —
  UV is the PIN.

## Operational

- **The flash log heals lazily**: deleting/superseding a record (e.g.
  enabling the soft-lock) leaves the old record in the log until compaction
  naturally overwrites it. At-rest guarantees harden over time rather than
  instantly. *(The superseded record is still sealed to the device root.)*
- **The board is the security boundary** — anyone with the device and your
  PIN is you. Same as every security key.
