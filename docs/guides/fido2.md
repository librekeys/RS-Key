# FIDO2 / WebAuthn / U2F

The FIDO half of the device: passkeys, two-factor security-key logins, and
legacy U2F. It speaks CTAP2 (`FIDO_2_0`) and CTAP1 (`U2F_V2`) over the HID
interface, so standard WebAuthn browsers and OS dialogs drive it without any
extra software. It passes the FIDO Alliance Conformance Tools clean (CTAP2.3
235/0, U2F 55/0 — a self-run pass, not a paid certification; see
[testing](../testing.md#fido-conformance)), and what has been checked against
real client software is in the [interop matrix](../interop.md).

The default build enumerates as "RS-Key" — its own USB identity
(`0x1209:0x0001`, the pid.codes FOSS VID), not a YubiKey one
([build.md](../build.md)). FIDO clients don't care: browsers, `python-fido2`,
and libfido2 bind the FIDO HID usage page, not the VID/PID, so everything on this
page works regardless of USB identity. The one exception is `ykman`, which gates
on a "Yubico YubiKey" reader name and therefore needs the opt-in
`VIDPID=Yubikey5` interop build ([build.md](../build.md)). The reported firmware
version is `5.7.4`, which is what FIDO tooling reads back; it is a build constant,
not the RS-Key release.

## Touch is always required

On the default (touch) build **every** FIDO operation needs a press of the
**BOOTSEL button** — both registration (makeCredential) and login
(getAssertion). The firmware's user-presence bit is implicitly true and it does
**not** honour a request to skip it: WebAuthn `userVerification`/`up` cannot turn
the touch off, and OpenSSH's `-O no-touch-required` is silently ignored on this
device. A "no-touch" SSH key still asks for the touch at login. The LED tells
you when the device is waiting — see [led.md](led.md) for the colours. A request
times out after no touch (the browser shows its own timeout UI); no button wired
on a custom board means presence confirms instantly.

## Set a PIN first

```sh
rsk fido set-pin            # set, or change once one exists
ykman fido access change-pin   # the same operation via ykman (needs the VIDPID=Yubikey5 build)
```

The clientPIN gates credential creation once it exists, and unlocks anything a
site requests user verification (UV) for. Rules from the firmware:

| | Value |
|---|---|
| Length | 4–63 characters (6–63 on the `fips-profile` build) |
| Per-power-cycle | 3 wrong attempts → `PIN_AUTH_BLOCKED` (`0x34`), re-plug to retry |
| Retry budget | 8 wrong attempts (across power cycles) |
| On exhaustion | PIN locks **until a factory reset** — no separate unblock |

After 3 wrong attempts in a single power cycle the device returns
`PIN_AUTH_BLOCKED` (`0x34`) and refuses more PIN entry until you unplug and
re-insert it; the 8-attempt budget is the across-power-cycle hard limit.

The retry counter resets on a correct PIN. There is no PUK or admin override:
once it is locked, the only way back is `ykman fido reset`, which wipes
everything (below). `rsk fido set-pin` asks for the current PIN when changing,
the new one twice, and prints the resulting `clientPin` state.

Once a PIN is set, makeCredential refuses to run without it (CTAP
`PUAT_REQUIRED`, `0x36`) — the browser collects the PIN and retries. That is
expected, not a fault.

## Passkeys (resident / discoverable credentials)

Register on any site offering a passkey or "security key" method — the browser
drives the device; you touch the button when the LED pulses. These are stored on
the device and surface at login without the site sending an allow-list.

Capacity: **256** resident passkeys (and 256 relying parties), flash-bound. When
the store is full, makeCredential returns `KEY_STORE_FULL` (`0x28`) and the
browser reports the key is out of space — delete some first.

Inspect and clean up (PIN required — credentialManagement is PIN-gated):

```sh
rsk fido list-passkeys              # relying parties + user handles + free slots
ykman fido credentials list        # same, via ykman (needs the VIDPID=Yubikey5 build)
ykman fido credentials delete <id>  # remove one (same build; browsers expose this too)
```

`rsk fido list-passkeys` prints the existing count and remaining slots, then each
relying party with its user names and a credential-id prefix. There is no
`rsk`-native delete yet; use `ykman` or the browser/OS passkey manager for that.

**credProtect.** A site can mark a passkey UV-required (credProtect level 3); the
firmware then hides it from discovery and from exclude-list checks until you
verify with the PIN, so it never leaks its existence to an unauthenticated
caller. RS-Key applies a credProtect level only when the relying party asks for
one — it does not silently force a default.

## Second-factor registrations (non-resident)

The classic security-key flow (GitHub, Google, GitLab, …) stores **nothing** on
the device. The credential is derived deterministically from the master seed and
handed back as an opaque id the site presents at login. This path is effectively
unlimited (it costs no flash), and the registrations survive a
[seed backup → restore](seed-backup.md) onto a new board — the same derivation
on the same seed reproduces the same keys.

Legacy **U2F** (CTAP1, `U2F_V2`) works the same way for older 2FA setups: the
register/authenticate pair is non-resident, with a monotonic signature counter,
attested by the device's end-entity certificate.

## Advertised algorithms

getInfo advertises these COSE algorithms; a relying party picks one in its
`pubKeyCredParams`:

| COSE alg | Curve / scheme | Notes |
|---|---|---|
| `-7` ES256 | NIST P-256 | the universal default |
| `-8` EdDSA | Ed25519 | |
| `-35` ES384 | NIST P-384 | slow keygen/sign (pure-Rust arithmetic) |
| `-36` ES512 | NIST P-521 | slow keygen/sign |
| `-47` ES256K | secp256k1 | dropped from new credentials on `fips-profile` |

The curve-explicit COSE ids (`-9` ESP256, `-19` Ed25519, `-51` ESP384, `-52`
ESP512) are also accepted in `pubKeyCredParams`. RS-Key selects the **first**
supported algorithm a site offers, so put your preferred curve first in the list.

## Post-quantum credentials

The device also implements **ML-DSA-44** (FIPS 204, COSE `-48`) makeCredential /
getAssertion, and — by deliberate exception — *prefers* it whenever a site lists
it, even after a classic algorithm. Nothing mainstream requests it yet; a client
that does (e.g. a `python-fido2` script offering `-48`) gets a PQC credential
today.

The getInfo advertisement is build-gated behind `advertise-pqc`
([build.md](../build.md)) because shipped Firefoxes (authenticator-rs before
2026-06-02) hard-fail the whole getInfo parse on an unknown COSE id. The
*capability* is always on; only the advertisement is opt-in. ML-DSA-65/-87
(`-49`/`-50`) are recognised but have no enabled backend.

## Extensions supported

getInfo advertises seven extensions:

| Extension | What it does | Limit |
|---|---|---|
| `hmac-secret` | per-credential secret keyed by a salt (the WebAuthn PRF maps onto it) | 32-byte output |
| `hmac-secret-mc` | the same evaluation at registration time | |
| `credProtect` | UV-gated credential visibility (levels 1–3) | |
| `credBlob` | small opaque blob stored with the credential | 128 bytes |
| `largeBlobKey` + large blobs | per-credential key into a device blob store | 2 KB store |
| `minPinLength` | the device hands its PIN-length policy to the RP | |
| `thirdPartyPayment` | the secure-payment-confirmation marker | |

Enterprise attestation is supported but off until enabled; the `ep` option flips
to true once an org key is installed — see [attestation.md](attestation.md).

## Factory reset

```sh
ykman fido reset            # needs the VIDPID=Yubikey5 build; or any WebAuthn "reset security key" UI
```

Wipes **all** FIDO state — resident passkeys, the PIN, the master seed (so all
derived non-resident credentials and U2F registrations die too) — and
regenerates a fresh identity and signature counter. The OpenPGP / PIV / OATH
applets are untouched: each applet's reset wipes only its own files, and a FIDO
reset deliberately steps around them even where the file ids interleave.

The wipe is gated by a physical touch. The familiar "reset only within 10 s of
plug-in" anti-accidental-reset gate is enforced client-side by `ykman` and the
browser, not by the firmware itself.

## Troubleshooting

- **"device not eligible / already registered"** — expected: the site sent an
  exclude-list matching a credential already on the device.
- **"PIN required" / repeated PIN prompts at registration** — a PIN is set, so
  makeCredential needs it (`PUAT_REQUIRED 0x36`). Enter it; if you have
  forgotten it, only a reset clears it.
- **A site demands UV but you have no PIN** — set one (`rsk fido set-pin`); UV on
  this device means the FIDO PIN.
- **"no space" / store-full at registration** — 256 resident passkeys is the cap
  (`KEY_STORE_FULL 0x28`); delete some with `ykman fido credentials delete` (needs
  the `VIDPID=Yubikey5` build) or your browser/OS passkey manager.
- **`rsk fido …` says "missing dependency: python-fido2"** — run `rsk` from
  inside `nix develop`; the management commands need the `python-fido2` library.
- **A "no-touch" SSH key still asks for a touch** — by design; the firmware
  always polls the button (see the top of this page). For the `ssh-keygen` PIN /
  touch / resident flags, see [ssh.md](ssh.md).
- **Linux permissions / the device is invisible to the browser** — udev rules in
  [linux.md](../linux.md).
