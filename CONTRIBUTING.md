# Contributing

Patches welcome — protocol features, board support, host tooling, docs, test
coverage. This file is the short version of how changes land without friction.
If something here contradicts what you see in the tree, the tree wins; send a
fix for this file too.

One thing before anything else: **exploitable bugs go through
[private reporting](SECURITY.md), not a public issue or PR.**

## Setup

```sh
nix develop
```

That is the whole setup: Rust stable with the `thumbv8m.main-none-eabihf`
target, picotool, gitleaks, cargo-audit/deny, the Python stack for `rsk` and
the device tests. Entering the shell also symlinks the repo's pre-commit hook
(gitleaks + fmt + clippy on the staged diff) into `.git/hooks` — commits from
outside the shell will fail on the hook, which is mildly annoying and entirely
intentional.

No Nix? `rust-toolchain.toml` pins the toolchain, target and components for
rustup, and you're on your own for picotool, gitleaks and the Python
dependencies. It works; it's just more moving parts to keep in sync.

## The gate

```sh
./scripts/check.sh
```

Everything that has to be green before a merge: rustfmt, clippy twice
(embedded and host-test profiles), the host test suite, the fips-profile test
flavor, both firmware images, the rsk-wipe image, cargo-audit, cargo-deny,
gitleaks. CI runs exactly this script (`.github/workflows/ci.yml`), so green
locally means green on the PR — there is no CI-only logic to discover later.

The default host target is `aarch64-apple-darwin` because that's where
development happens; on Linux run `HOST_TARGET=x86_64-unknown-linux-gnu
./scripts/check.sh`.

One trap worth knowing: check.sh builds the firmware twice into the *same
path* — the real (touch-enabled) image first, then the no-touch test image
that the automated suites need. After a check.sh run,
`target/.../release/firmware` holds the **no-touch** build. Rebuild with
`cargo build --release -p firmware` before flashing anything you intend to
use. Yes, this has bitten us; the touch and no-touch images are otherwise
indistinguishable until a credential gets minted without anyone touching the
button.

## Code

The firmware crates are `no_std`, no alloc. If a change needs a heap, the
change is wrong.

Clippy runs with `-D warnings` on both profiles. Don't silence a lint without
saying why on the `#[allow]` line — and silence it at the smallest scope that
works.

`unsafe` is the expensive keyword. There are currently two audited exception
areas, both documented in [docs/unsafe.md](docs/unsafe.md); a new `unsafe`
site needs an entry there explaining why safe Rust can't do the job. PRs that
add undocumented `unsafe` don't get merged, full stop.

Every file starts with the SPDX header:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
```

Comments explain constraints, not mechanics — the reader can see *what* the
line does. Flash-layout decisions, spec-section references (`// CTAP 2.1
§6.5.5.7`), power-cut ordering, those are worth words.

New dependencies are a conversation, not a default. cargo-deny enforces
licenses and advisories mechanically, but the real bar is: does this belong
in an authenticator's trust base? Say in the PR what the crate buys us.

For the Python side (`tools/rsk`): match the neighbouring modules — argparse
subcommand groups via `register(sub)`, `die()` for errors, 4-space indents,
dependencies provided by the flake (don't reach for pip).

## Firmware changes bump bcdDevice

Any change to device behavior bumps `config.device_release` in
`firmware/src/main.rs` by one (hex). It's the build counter: `rsk inventory
list` reports it, fleet records key on it, and "which build is this key
actually running" stops being archaeology. Host-only changes (CLI, docs, CI)
don't bump it.

Don't confuse it with the **anti-rollback epoch** — a separate, much coarser
number that is *not* in `main.rs`. The epoch is a `picotool seal --rollback N`
argument applied when you flash, and it advances only for a release a
downgrade would reopen (a fixed exploitable bug), never per change: the OTP
thermometer has 48 steps for the board's life. So a PR doesn't "bump" it —
at most it flags that the next release should. See
[docs/production.md](docs/production.md#stage-3--anti-rollback-optional),
stage 3.

## Tests

- **Host**: `cargo test` across the workspace crates — part of the gate, runs
  everywhere, no hardware.
- **On-device**: `tests/*.py`, run by hand against a board flashed with the
  **no-touch test build** (otherwise every makeCredential waits for a finger
  that never comes). See [docs/testing.md](docs/testing.md).
- **Fuzzing**: every external-facing parser has a target —
  `nix develop .#fuzz -c cargo fuzz run <target>`. New parser, new target;
  a fuzz target that found nothing is still evidence.

A protocol-visible change should come with a test at the level where it's
visible: a host test if the logic is host-testable, a `tests/` script if only
the real USB stack exercises it.

## Commits and PRs

Commit subjects use the zone prefix you see in `git log` — `fido:`, `piv:`,
`rsk:` (host CLI), `docs:`, a crate or area name for anything else
(`fido,piv:` when one change genuinely spans two). History reads as a
changelog; keep it that way. Signed commits are appreciated but not required.

Small PRs merge fast. One topic per PR; refactors separate from behavior
changes; the PR template's checklist is short on purpose — if a box doesn't
apply, delete it rather than ticking it on faith.

If a change touches the protocol surface or persistent flash layout, expect
questions about upgrade behavior: what happens to a device that already has
data written by the previous build? "It keeps working" needs to be true and
ideally demonstrated.

## License

AGPL-3.0-only, same as upstream pico-keys. By contributing you agree your
work is licensed under it. Keep the SPDX headers, don't vendor incompatible
code, and if a file derives from someone else's work, say so where the file
says it.
