# Fleet tooling

Inventory, identity verification, and offboarding for a fleet of RS-Keys.
Three commands: `rsk inventory list` (what is this key, touch-free),
`rsk inventory verify` (is this key the one we enrolled), `rsk offboard`
(wipe a returned key and keep a signed receipt).

## Inventory

```sh
rsk inventory list          # human-readable, one block per key
rsk inventory list --json   # one JSON object per line, for scripting
```

Walks every connected key over both transports and prints one record per
device — serial, firmware version, bcdDevice (the build counter), secure-boot
state, flash usage, FIDO options, backup/soft-lock state, org-attestation
state:

```
device 37bebfdca282523b  (ccid+hid)
  firmware   : 5.7.4  bcdDevice 0x0748  sdk 8.6
  secure boot: LOCKED  (bootkey 0x0)
  flash      : 16711/1572864 B used, 469 files
  fido       : U2F_V2, FIDO_2_0  clientPin=True
  backup     : sealed=False has_seed=True  seed lock: off
  org attest : installed  chain sha256 74d9f98c3fb0bb5c…
```

The serial is the RP2350's OTP chip id, read from the rescue applet's SELECT
response — unique per chip, unlike the USB descriptor serial (identical across
devices). Everything `list` reads is gate-free: no PIN, no touch, safe to run
against a hub full of keys.

With several keys connected the CCID and HID transports cannot be matched to
one another, so the records stay separate (tagged `ccid` / `hid`); plug keys
in one at a time when you want merged records.

## Identity verification

```sh
rsk inventory verify                            # print the fingerprint (touch)
rsk inventory verify --expect-key 66573f74ca06359a   # pin it (--pin if set)
```

Challenge-response against the device's attestation key: the host sends a
fresh 16-byte challenge, the device signs it (vendor `AUDIT_CHECKPOINT`) with
the ECDSA P-256 key derived from its OTP DEVK, and the host verifies the
signature. The printed fingerprint (SHA-256 of the public key, first 16 hex
digits) is the same one `rsk audit verify` prints — one identity anchor for
both workflows.

```mermaid
sequenceDiagram
    participant H as Host
    participant D as Device
    H->>D: fresh 16-byte challenge
    D-->>H: ECDSA-P256 signature (OTP-DEVK key) + public key
    H->>H: verify signature, match fingerprint vs record
```

This only proves identity once the device has a provisioned OTP DEVK; on an
unprovisioned dev board there is no device-bound key and `verify` is refused.

**Enrollment:** when you hand a key out, run `rsk inventory verify` once and
record `serial + fingerprint`. Any later verify with
`--expect-key <fingerprint>` (or the full SEC1 public key) proves you are
talking to that physical chip — a clone without the OTP DEVK cannot answer.
Every verify is itself journaled as a `CHECKPOINT` event, so the device's
[audit log](audit.md) shows each time it was checked.

## Offboarding

```sh
rsk offboard                      # guided, typed confirmation, ~3 touches
rsk offboard --report ret-42.json # choose the receipt path
```

Decommissions a returned key: wipes the OTP slots, OATH credentials, PIV
(block PIN+PUK, then factory reset), OpenPGP (block PWs, TERMINATE+ACTIVATE),
the FIDO seed/passkeys/PIN, and the [org attestation](attestation.md) — then
signs a final audit checkpoint over the post-wipe journal window and saves it
as a JSON receipt.

The receipt is a cryptographic statement that **this** device (attestation
fingerprint) was factory-reset (the signed window contains the `RESET` event):

```json
{
  "device": "37bebfdca282523b",
  "steps": {"otp": "ok", "oath": "ok", "piv": "ok", "openpgp": "ok",
            "fido_reset": "ok", "org_attestation": "cleared"},
  "journal_window": [{"seq": 412, "event": "RESET", "...": "..."}],
  "signed": true,
  "challenge": "…", "signed_head": "…", "seq": 414,
  "signature": "…", "attestation_pubkey": "04…",
  "fingerprint": "66573f74ca06359a"
}
```

To re-check it offline, verify `signature` (ECDSA P-256, SHA-256) over
`"RSK-AUDIT-CKPT-v1" ‖ signed_head ‖ seq (LE32) ‖ challenge` with
`attestation_pubkey`, and match `fingerprint` against your inventory record.

No PIN is needed anywhere in the flow — every wipe path is deliberately
reachable without credentials (the PIV/OpenPGP paths block the PINs first,
which is the spec's own anyone-can-reset design), so a key that comes back
with unknown PINs can still be offboarded. What it cannot do is *impersonate*:
nothing in the wipe path can read or export secrets.

OTP slots protected by an access code are the one exception — they refuse the
PIN-free delete; the receipt's `steps.otp` records which slots stayed. A
follow-up `rsk offboard` after recovering the code, or a full
[`rsk-wipe`](https://github.com/TheMaxMur/RS-Key/blob/main/rsk-wipe/README.md)
flash nuke, covers that case.
