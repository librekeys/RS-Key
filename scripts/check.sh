#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Full quality + security suite: formatting, lint, tests, no_std build, SCA, secrets.
# Run locally or in CI. Host target defaults to macOS arm64 (override with HOST_TARGET).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"

run() { echo; echo "== $1 =="; shift; "$@"; }

# flake.lock must stay in sync with flake.nix: regenerate the lock (without
# upgrading existing pins, unlike `nix flake update`) and fail if it changed. A
# stale committed lock means a "green" run no longer matches flake.nix, silently
# undermining the reproducible-build / SBOM provenance. Cheap when in sync (no
# fetch); only an added/removed input in flake.nix produces a diff.
lock_in_sync() {
  nix flake lock
  git diff --exit-code -- flake.lock
}

run "fmt"                      cargo fmt --all --check
run "clippy (embedded)"        cargo clippy --workspace -- -D warnings
run "clippy (host tests)"      cargo clippy -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue --target "$HOST" --all-targets -- -D warnings
# tools/tui is its own workspace (host-only), so the --all/--workspace runs
# above never see it — gate it explicitly. Its lockfile was scanned by nobody
# until Dependabot flagged a transitive advisory from the GitHub side.
run "fmt (tui)"                cargo fmt --manifest-path tools/tui/Cargo.toml --check
run "clippy (tui)"             cargo clippy --manifest-path tools/tui/Cargo.toml --target "$HOST" --all-targets -- -D warnings
# fuzz/ is also its own (nightly) workspace. rustfmt needs no toolchain, so the
# stable gate can format-check it here; building/clippy stay in the .#fuzz shell
# (deep-checks CI). Format fuzz/ with this same stable rustfmt — not the .#fuzz
# nightly one, which lays imports out differently.
run "fmt (fuzz)"               cargo fmt --manifest-path fuzz/Cargo.toml --check
run "test (host)"              cargo test -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue --target "$HOST"
# The PQC-advertisement opt-in changes the getInfo shape — test both forms.
run "test (advertise-pqc)"     cargo test -p rsk-fido --features advertise-pqc --target "$HOST" getinfo
# The FIPS-style profile changes algorithm menus / PIN floor / export policy;
# run its tests (name-filtered: the regular fixtures assume the 4-char PIN
# floor) and type-check the locked firmware image.
run "test (fips: rsk-fido)"    cargo test -p rsk-fido --features fips-profile --target "$HOST" fips
run "test (fips: rsk-piv)"     cargo test -p rsk-piv --features fips-profile --target "$HOST" fips
run "clippy (fips firmware)"   cargo clippy -p firmware --features fips-profile -- -D warnings
run "build firmware (release)" cargo build --release -p firmware
# The test build: no BOOTSEL presence, so the automated suites don't hang on a touch.
run "build firmware (test, --no-default-features)" cargo build --release -p firmware --no-default-features
run "build rsk-wipe (release)" cargo build --release -p rsk-wipe
run "flake.lock in sync"       lock_in_sync
# RUSTSEC-2023-0071: rsa Marvin timing side-channel — no fixed release; it is the
# OpenPGP RSA backend, mitigated by blinding. Justification in deny.toml.
run "cargo-audit (SCA)"        cargo audit --ignore RUSTSEC-2023-0071
run "cargo-audit (tui SCA)"    cargo audit --file tools/tui/Cargo.lock
run "cargo-deny"               cargo deny check
# Supply-chain provenance-of-review: every dependency must be covered by an
# imported audit (mozilla/google/isrg/zcash) or a recorded exemption. Fails when
# a new, unreviewed crate enters the tree. --locked uses the committed
# supply-chain/imports.lock (offline, no fetch). See docs/supply-chain.md.
run "cargo-vet (supply-chain)" cargo vet --locked
run "gitleaks (tree)"          gitleaks detect --redact --no-banner

echo
echo "ALL CHECKS PASSED"
