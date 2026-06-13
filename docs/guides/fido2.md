# FIDO2 / WebAuthn / U2F

The FIDO half of the device: passkeys, two-factor security-key logins, and
legacy U2F. Works with standard WebAuthn browsers and OS dialogs; what has
actually been checked is in the [interop matrix](../interop.md).

## Set a PIN first

```sh
rsk fido set-pin            # set, or change once one exists
```

The PIN gates credential creation (and anything a site requests user
verification for). 8 wrong attempts lock the PIN until a factory reset.
4–63 characters.

## Passkeys (resident credentials)

Register on any site offering "security key" as a passkey method — the
browser drives the device; you touch the button when the LED pulses.
Capacity: up to 256 resident passkeys (flash-bound).

Inspect / clean up:

```sh
rsk fido list-passkeys      # relying parties + user handles (PIN required)
ykman fido credentials list # same, via ykman
```

## Second-factor registrations (non-resident)

The classic security-key flow (GitHub, Google, …) stores **nothing** on the
device — the credential is derived from the master seed and handed back as
an id the site presents at login. Effectively unlimited, and they survive a
[seed backup → restore](seed-backup.md) onto a new board.

## Touch ( user presence )

Every FIDO operation needs a press of the **BOOTSEL button** on the default
build. The LED tells you when the device is waiting:
see [led.md](led.md) for colors. A request times out after ~15 s of no touch
(the browser shows its own timeout UI).

## Extensions supported

`hmac-secret` (and the PRF mapping sites use), `credProtect`, `credBlob`
(128 B), `largeBlobKey` + large blobs (2 KB store), `minPinLength`,
enterprise attestation (off unless enabled), `thirdPartyPayment`.

## Post-quantum credentials

The device implements **ML-DSA-44** (FIPS 204, COSE −48) makeCredential /
getAssertion. Nothing mainstream requests it yet; a client that does (e.g. a
python-fido2 script offering `-48` in `pubKeyCredParams`) gets a PQC
credential today. The getInfo advertisement is build-gated
(`advertise-pqc`, [build.md](../build.md)) because released Firefox chokes on
unknown algorithm ids; capability itself is always on.

## Factory reset

```sh
ykman fido reset            # or any WebAuthn "reset security key" UI
```

Wipes all FIDO state — resident passkeys, the master seed (⇒ all derived
non-resident credentials die too), the PIN — and regenerates a fresh
identity. OpenPGP/PIV/OATH applets are untouched: each applet's reset wipes
only its own files. The reset must happen within 10 s of plug-in, with a
touch — the standard FIDO anti-accidental-reset gate.

## Troubleshooting

- Browser says "device not eligible / already registered": expected — the
  site sent an excludeList matching an existing credential.
- A site demands UV but you have no PIN: set one (`rsk fido set-pin`).
- `ssh-keygen` PIN/touch specifics: [ssh.md](ssh.md).
- Linux permissions: [linux.md](../linux.md).
