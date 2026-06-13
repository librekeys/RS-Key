# PIV

A PIV smart-card (NIST SP 800-73) over CCID: X.509 client certificates,
S/MIME, PIV-aware OS login, PKCS#11. Driven with `ykman piv`.

## Defaults

| | Default |
|---|---|
| PIN | `123456` |
| PUK | `12345678` |
| Management key | AES-192, the well-known default |

Change all three before real use:

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

## Slots

The standard four — `9a` (authentication), `9c` (signing), `9d` (key
management), `9e` (card auth) — plus the twenty retired key-management
slots (`82`–`95`) and `f9` (attestation). Algorithms: ECC P-256/P-384,
RSA 1024/2048.

## Generate a key + certificate

```sh
ykman piv keys generate 9a pub.pem                  # on-card key
ykman piv certificates generate 9a pub.pem -s "CN=me"   # self-signed cert
ykman piv info
```

Or a CSR for a real CA: `ykman piv certificates request 9a pub.pem me.csr`.

**Attestation:** `ykman piv keys attest 9a attestation.pem` proves the key
was generated on-device, chained through the `f9` slot
(`O=RS-Key` certificates).

Touch policy per key: `ykman piv keys generate --touch-policy always …` —
each private-key operation then needs a button press.

## Use it

- **PKCS#11** (browsers, ssh, VPNs): point the app at your distro's
  `opensc-pkcs11.so`; the card shows up as a PIV token.
- **Windows/macOS native** smart-card stacks pick PIV up as-is.
- `ssh` via PKCS#11: `ssh -I /usr/lib/opensc-pkcs11.so you@host`.

## At rest

PIV private keys are stored **AES-GCM-sealed** under the device root. Once the
OTP master key is [fused](../production.md), a flash dump does not yield key
material; **before** that burn the seal's root derives from on-chip state that
an attacker with the flash and chip could reconstruct, so at-rest protection is
only meaningful after provisioning (see [threat-model.md](../threat-model.md)).

## Factory reset (PIV only)

```sh
ykman piv reset
```

Wipes PIV keys/certs/PINs only; the other applets are untouched.

## Troubleshooting

- `ykman` can't connect → [linux.md](../linux.md) (pcscd + scdaemon notes).
- PIN blocked → `ykman piv access unblock-pin` (needs PUK); PUK blocked too →
  `ykman piv reset`.
- RSA-2048 generate takes ~20 s — that's the hardware, not a hang (the
  device keeps the connection alive).
