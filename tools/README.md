# `rsk` — RS-Key device CLI

The host-side CLI for [RS-Key](https://github.com/TheMaxMur/RS-Key): device
status, wallet-style seed backup, secure-boot provisioning, OTP/MKEK burn, FIDO2
management, OpenPGP reset, audit-journal verification, and more.

Inside the repo's Nix dev shell `rsk` is already on `PATH`. This package exists
so you can run it **without Nix** on any host with Python ≥ 3.9.

## Run without Nix

With [uv](https://docs.astral.sh/uv/) (no install step — ephemeral env), from
the repo root:

```sh
uvx --from ./tools rsk status
uvx --from ./tools rsk --help
```

Or install it as a persistent tool:

```sh
uv tool install ./tools      # then: rsk status
# or, classic pip / pipx:
pipx install ./tools
pip install ./tools
```

For repeated use during development, `cd tools && uv run rsk status` reuses one
environment.

### Native dependencies

Two wheels wrap system libraries:

- **`hidapi`** (CTAPHID transport) and **`pyscard`** (PC/SC, the CCID applets).
- macOS ships both frameworks; wheels work out of the box. On Apple Silicon, if
  pip pulls a universal2 `pyscard` that crashes, force an arm64 rebuild:
  `ARCHFLAGS="-arch arm64" pip install --no-binary pyscard pyscard`.
- On Linux install `pcsclite`/`libpcsclite-dev` and a running `pcscd` for the
  CCID half (PIV/OATH); see [docs/linux.md](../docs/linux.md). HID needs udev
  rules for non-root access.

## Tests

The pure-logic unit tests need no device:

```sh
uv run --with pytest --extra test python -m pytest rsk/test_common.py rsk/test_secureboot.py
```

The on-device test suites under [`../tests/`](../tests) need real hardware and
run from the Nix dev shell.
