# tests/interop — real-world consumer sweep

The layer above protocol conformance: does the device work with the actual
software a user runs (`gpg`, `ssh`, `ykman`, `fido2-token`, OpenSC), not with
our own APDU/CBOR scripts. This is the executable companion to
[../../docs/interop.md](../../docs/interop.md) — read that for the full matrix,
the status legend, and the touch-vs-no-touch build split.

```sh
nix develop -c python tests/interop/run.py            # read-only CLI cells
nix develop -c python tests/interop/run.py --touch    # also touch cells (need a press)
nix develop -c python tests/interop/run.py --json      # machine-readable
```

- Discovers the device via `fido2-token -L` (HID) and `ykman info` (CCID); a
  missing transport or tool is a **SKIP**, not a failure.
- Every default probe is **read-only**. Touch cells (`--touch`) need a finger
  on the BOOTSEL button and the touch firmware build. `--destructive` is
  reserved for future enrol/keygen cells (none yet).
- Exit status is non-zero iff a probe that actually ran FAILED.

Adding a probe: append to the `PROBES` table in `run.py` with a small
`p_*(env)` function returning `(status, detail)`. Keep it read-only unless it
is gated behind `--destructive`.
