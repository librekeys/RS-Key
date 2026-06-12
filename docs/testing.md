# Testing

Four layers, fastest first. The protocol and applet crates are
hardware-agnostic on purpose — only `firmware` touches the HAL — so
everything except board bring-up is tested and fuzzed on the host, with the
device reserved for end-to-end integration.

| Layer | What it checks | Where |
|---|---|---|
| Host unit tests | parsers, state machines, applets, crypto (~350 tests) | `#[cfg(test)]` in each crate |
| Fuzzing | the same logic under adversarial bytes | `fuzz/` |
| Miri | the fuzz targets' logic under the UB checker | `fuzz/tests/miri.rs` |
| `no_std` build | the crates still link for the device | default `thumbv8m` target |
| On-device tests | real USB + flash on the board | `tests/*.py` |

## The one command

```sh
nix develop -c ./scripts/check.sh
```

runs fmt, clippy (embedded **and** host targets, `-D warnings`), all host
tests, both firmware builds (touch + no-touch), the rsk-wipe build,
`cargo-audit`, `cargo-deny` and `gitleaks`. Green check.sh is the bar for
every commit.

## Host tests

`cargo test` must target the host explicitly (the workspace defaults to
`thumbv8m`):

```sh
nix develop -c cargo test -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto \
    -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-mgmt -p rsk-oath \
    -p rsk-otp -p rsk-piv -p rsk-rescue --target aarch64-apple-darwin
```

(`HOST_TARGET` env overrides the triple in `check.sh`.) Crypto tests pin
NIST/RFC vectors; applet tests drive full protocol flows (register → assert,
PIN lockout ladders, OpenPGP import → sign → verify against `RustCrypto`,
PIV generate → attest → parse with `x509-parser`).

## Fuzzing

Every parser **and every applet's full dispatch** has a `cargo-fuzz` target —
30+ of them: APDU, BER-TLV, CTAPHID reassembly (+ round-trip property), CCID
framing, all the FIDO command surfaces (CBOR dispatch, credentials,
credMgmt, U2F, extensions, large blobs, the vendor backup/lock commands —
half that corpus runs soft-locked), OpenPGP dispatch + the EC/RSA crypto
parsers, OATH/OTP/PIV/management/rescue dispatch, the keyboard frame codec,
the phy TLV codec (parse∘serialize round-trip is an asserted invariant), the
PIN protocols, AEADs, the DRBG, ML-DSA/ML-KEM decoding, and the seed-blob
format/migration state machine.

```sh
nix develop .#fuzz -c cargo fuzz list
nix develop .#fuzz -c cargo fuzz run <target> -- -max_total_time=60
```

The fuzz workspace is separate (nightly + libfuzzer) and is **not** built by
check.sh — after changing a shared type, `nix develop .#fuzz -c cargo fuzz
build` to catch drift. House rule: new attacker-facing parser or dispatch
surface ⇒ new fuzz target in the same change.

**Miri** runs every target's logic once more as plain tests under the UB
checker — undefined behavior instead of panics (`fuzz/tests/miri.rs`; the
`MIRIFLAGS` policy is set by the `.#fuzz` shell):

```sh
nix develop .#fuzz -c cargo miri test --manifest-path fuzz/Cargo.toml
```

Neither suite gates a commit. CI runs both weekly — the `deep-checks`
workflow: the Miri suite, plus a timed libFuzzer pass over every target with
the corpus carried between runs, crash artifacts uploaded.

## On-device tests

Numbered, self-contained scripts under `tests/`, run from the dev shell
against a flashed board:

```sh
nix develop -c python tests/10_fido_getinfo.py
nix develop -c python tests/80_piv.py
nix develop -c python tests/75_seed_backup.py --pin <your PIN>
```

- Most need the **no-touch build** (`--no-default-features`) — they cannot
  press the button. If the board runs secure boot, sign the test build too.
- Numbering: `0x` transport smoke, `1x` FIDO basics, `2x` FIDO full,
  `3x/4x/5x` OpenPGP, `6x` PQC, `7x` management/OATH/OTP/backup/lock,
  `8x` PIV/rescue, `9x` OTP-fuse migration.
- Tests that reboot the device do it hands-free over CCID and wait for
  re-enumeration; tests are idempotent where the applet allows it and say so
  in their docstring when they are destructive (resets).
- The FIDO PIN is never guessed: destructive PIN tests take `--pin`
  explicitly.

Two external suites validated the implementation: Yubico's python-fido2
test corpus and the Gnuk/OpenPGP card suite (see
[third_party/](../third_party/) if vendored, or run them from their
upstream checkouts).

## CI parity

`check.sh` is plain bash over the Nix dev shell — a CI job is
`nix develop -c ./scripts/check.sh` plus, on a runner with the board
attached, the `tests/` scripts. The scheduled `deep-checks` workflow is the
two commands from this page, weekly. No hidden state.
