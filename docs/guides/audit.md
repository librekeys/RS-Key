# Audit journal

A tamper-evident, on-device log of security events: boots, FIDO registrations
and logins, factory resets, PIN set/change/lockouts, policy changes, seed
backup and soft-lock activity.

```sh
rsk audit log              # export + print (add --pin if a PIN is set)
rsk audit verify           # log + DEVK-signed checkpoint (touch)
rsk audit verify --expect-key <hex>   # also pin the enrolled attestation key
```

## What it records

| event | detail |
|---|---|
| `BOOT` | first journal touch of each power cycle |
| `MAKE_CREDENTIAL` / `GET_ASSERTION` / `U2F_*` | first 8 bytes of the rpIdHash (pseudonymous) |
| `RESET` | factory reset (survives it — see below) |
| `PIN_SET` / `PIN_CHANGE` / `PIN_LOCKOUT` | lockout aux: 0 = retries exhausted, 1 = per-boot block |
| `CFG_MIN_PIN` / `CFG_ENTERPRISE_ATT` | aux = new minimum / detail[0] = forceChangePin |
| `LOCK_ENGAGE` / `LOCK_RELEASE`, `BACKUP_*` | soft-lock and seed-backup lifecycle |
| `ATT_IMPORT` / `ATT_CLEAR` | [org attestation](attestation.md) provisioning |
| `CHECKPOINT` | every signed checkpoint is itself logged |

There is **no wall clock** on the device: entries carry the boot-relative
uptime, every power cycle opens with a `BOOT` entry, and the sequence number
gives total order. Wall-clock attribution is the host's job (e.g. record when
you ran `rsk audit verify`).

## How the tamper evidence works

The journal is a 128-entry flash ring. Each entry extends a SHA-256 hash
chain; when the ring is full, the oldest entry is folded into an **epoch**
accumulator before its slot is reused — so evicted history stays attested in
aggregate even though its details are gone. The chain head is
`fold(epoch, window)`.

```mermaid
flowchart TD
    e["new event"] --> chain["SHA-256 hash chain (window)"]
    chain -->|ring full| fold["fold oldest into epoch accumulator"]
    fold --> reuse["slot reused"]
    chain --> head["chain head = fold(epoch, window)"]
```

`rsk audit verify` sends a fresh 16-byte challenge; the device signs
`head ‖ seq_next ‖ challenge` with an ECDSA P-256 key derived from the
**OTP DEVK** ([production.md](../production.md) stage 1) and returns the
signature plus its public key. The host refolds the exported window and
checks both. Record the printed attestation key once at provisioning; pin it
with `--expect-key` afterwards — a mismatch means a different (or
cloned-without-fuses) device.

Meta updates are ordered so that a power cut at any point loses at most the
newest event and never produces a false tamper verdict.

## Reset semantics (privacy by design)

`authenticatorReset` does **not** erase the journal — it *folds* the whole
window into the epoch and deletes the per-event details, then logs the
`RESET`. A handed-over device therefore proves "N events happened, then a
reset" without revealing where it had been used. The chain (and the
checkpoint key) continue uninterrupted across resets.

## Gating

- `AUDIT_READ` (export): pinUvAuthToken with the `acfg` permission when a PIN
  is set; otherwise open. Entries are pseudonymous — rpIdHash prefixes, never
  RP names or user handles.
- `AUDIT_CHECKPOINT`: the same PIN gate **plus a physical touch**, and it
  refuses entirely without a provisioned OTP DEVK — an attestation that
  anyone could re-derive would be theatre.

## What it does and does not prove

The log is written by the firmware, so its honesty is rooted in the boot
chain: with **secure boot + the OTP master key** ([production.md](../production.md))
only your signed firmware can append to the journal or wield the checkpoint
key, and a flash dump cannot forge it. On an unprovisioned dev board the
journal still works as a debugging aid, but `verify` is refused — there is no
device-bound key to sign with, and a checkpoint without one would prove
nothing.
