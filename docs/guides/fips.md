# FIPS-style profile (`fips-profile`)

An **opt-in build flavor** that bakes a locked, FIPS-style algorithm policy
into the image. Nothing is removed from the codebase or from the default
build — without the flag the firmware is byte-for-byte the usual one. With
it, the policy is part of the signed image, and once
[secure boot](../production.md) is enabled the device runs nothing but that
signed image: a policy you cannot toggle off at runtime, because there is no
runtime knob to toggle.

```sh
cargo build --release -p firmware --features fips-profile
# then sign + flash as usual (production.md)
```

> **A profile, not a validation.** Nothing here is FIPS 140-3 *validated* —
> no CMVP certificate, no validated module boundary. This profile restricts
> the device to FIPS-approved *algorithms* and documents exactly where the
> line is drawn.

## What the profile locks

| Area | Default build | `fips-profile` build |
|---|---|---|
| FIDO algorithms | ES256, EdDSA, ES384, ES512, ES256K, ML-DSA-44 | drops **ES256K** (secp256k1 — never NIST-approved) |
| FIDO minimum PIN | 4 | **6** (and `setMinPINLength` can only raise it) |
| Seed backup | one-time export window | **export refused** — non-exportable key material; restore (`BACKUP_LOAD`) still works, so keys may migrate *into* a profile device, never out |
| PIV management key | 3DES or AES | **no new 3DES keys** (SP 800-131A); an existing 3DES key still authenticates so a reflashed device can migrate itself to AES |
| PIV RSA | 1024 / 2048 | **no RSA-1024** generation or import |

## What deliberately stays

- **Ed25519 / X25519** — approved by FIPS 186-5 (EdDSA) and SP 800-186;
  `ssh ed25519-sk` keeps working.
- **ML-DSA-44** — FIPS 204. The post-quantum path is the *point*, not an
  extra.
- **HMAC-SHA-1 in OATH HOTP/TOTP** — RFC 4226 mandates it, and HMAC-SHA-1
  (unlike bare SHA-1 signatures) remains approved.
- **Existing credentials.** A secp256k1 credential created by a default
  build still asserts; the profile gates *creation*, not your ability to log
  in. Same for an existing 3DES management key (auth works, replacement must
  be AES) and existing RSA-1024 PIV keys.

## Verifying a device runs the profile

`ykman fido info` (or any getInfo dump) on a profile build shows
`minPinLength: 6` and no `-47` in the algorithms list. Combined with secure
boot, the firmware's own signature is the policy attestation: only your
signed profile image boots.

## Why compile-time

A runtime "FIPS mode" toggle is one admin command away from not being FIPS
mode. A compile-time profile under secure boot is a different object: the
restricted menu is the only code in the image, the image is signed, and the
fuses only boot your signatures. Changing the policy means signing a
different image — which is exactly the auditable event you want it to be.
