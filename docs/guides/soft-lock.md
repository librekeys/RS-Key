# Soft-lock — at-rest seed lock

Optional hardening: with the lock engaged, the FIDO master seed exists in
flash **only** encrypted to a 32-byte key that you hold (as BIP-39/SLIP-39
words or hex). A stolen board — even powered up, even running genuine
firmware — refuses every FIDO operation until that key is presented. Your
identity becomes *device + words*, two factors.

This is the same idea as a wallet passphrase, and it composes with (does not
replace) the silicon protections: once provisioned, the OTP root and secure
boot ([production.md](../production.md)) stop flash-dump and foreign-firmware
attacks; the soft-lock additionally stops *your own device in the wrong
hands*.

```mermaid
stateDiagram-v2
    [*] --> Sealed: normal (device-root-sealed seed)
    Sealed --> Locked: rsk lock enable (PIN + touch)
    Locked --> Unlocked: rsk lock unlock (256-bit key)
    Unlocked --> Locked: power cycle / unplug (RAM zeroized)
    Unlocked --> Sealed: rsk lock disable (PIN + touch)
```

## Enable

```sh
rsk lock enable            # PIN + touch gated; typed confirmation
```

Prints the lock key **once** (choose words or hex), wraps the seed with
ChaCha20-Poly1305 under it, deletes the plaintext-sealed copy. Treat the key
like the backup words: paper, not a file.

## Daily use — unlock at power-up

```sh
rsk lock status            # locked?
rsk lock unlock            # paste the words/hex; seed goes to RAM only
```

The lock re-engages at **every power cycle** (the unlocked seed lives only
in RAM and is zeroized). A locked device answers FIDO requests with an
"operation denied" status — browsers show a generic failure, ssh says the
key refused — until unlocked. Unlock needs no PIN or touch: knowledge of the
256-bit key *is* the authorization, and it runs headless in scripts fine.

## Disable

```sh
rsk lock disable           # needs an unlocked session + PIN + touch
```

Restores the normal plaintext-at-rest (device-root-sealed) seed.

## Lost the lock key?

Unrecoverable by design. The way forward is a FIDO factory reset, which
deletes the locked blob and generates a fresh identity (your
[seed backup](seed-backup.md), if you made one *before* locking, still
restores the old identity afterwards).

## Honest caveats

- The flash log keeps the superseded plaintext-sealed record until natural
  compaction overwrites it — the at-rest guarantee hardens over time after
  ENABLE rather than instantly. (That lingering record is still sealed to
  the device root, so this only matters against an attacker who has also
  defeated the OTP tier.)
- A compromised host at unlock time cannot read the key from the wire (the
  channel is encrypted) or the seed (never leaves the device) — but while
  the device sits unlocked and plugged in, it can drive normal FIDO
  operations, like any session. Unplug when done.
