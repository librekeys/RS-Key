# Enterprise attestation (org provisioning)

Out of the box every RS-Key attests with a per-device self-signed certificate
(built over the seed at first boot). An organization can replace that with its
**own attestation key and certificate chain**, so its relying parties can
verify "this credential was created on one of *our* keys" (the CTAP 2.1
enterprise-attestation feature).

```sh
# generate an org attestation CA + leaf however your PKI does it, then:
rsk fido attestation import --key org-att.pem --chain org-chain.pem [--pin …]
rsk fido attestation status
rsk fido attestation clear [--pin …]
```

## What changes once a chain is installed

- **makeCredential with `enterpriseAttestation` 1 or 2** (sent by managed
  platforms) returns a full attestation: signature by the org key, `x5c` =
  your chain (leaf first, up to 4 certs / 2048 bytes), `epAtt = true`.
  Without the org chain, level 2 falls back to the per-device key and its
  self-signed cert, exactly as before.
- **U2F registration** attests with the chain's leaf instead of the
  self-signed device cert (classic batch attestation).
- **Ordinary makeCredential is untouched** — self-attestation, no chain, no
  cross-site trackable identifier. EA fires only when the platform explicitly
  asks for it *and* `enableEnterpriseAttestation` (authenticatorConfig) is on.

`enableEnterpriseAttestation` itself now **persists across power cycles**
until a factory reset, as CTAP 2.1 specifies (it used to be RAM-only).

## Transport and gating

The P-256 private key crosses the wire ChaCha20-Poly1305-wrapped on the same
ephemeral-ECDH channel the seed backup uses; the chain is public certificate
material and travels in the clear, MAC-covered by the PIN token. Import and
clear are gated like a seed move: **channel + PIN (when set) + physical
touch**, and both are recorded in the [audit journal](audit.md)
(`ATT_IMPORT` / `ATT_CLEAR`).

On the device the key is sealed under the same kbase arms as the master seed
— burn the [OTP master key](../production.md) *before* importing and the
sealed key is rooted in fuses, not just flash.

## Reset semantics

The org attestation **survives `authenticatorReset`** — it is org-provisioned
device identity, not user data (the reset itself lands in the audit journal).
Removing it is an explicit, gated `attestation clear`.

## Privacy note

A shared org chain makes credentials linkable *to the organization* across
its RPs — that is its purpose. It is served only on explicit EA requests; if
you do not work for an org that provisioned your key, this entire page is a
no-op for you.
