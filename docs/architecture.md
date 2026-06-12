# Architecture

How the firmware is put together — for contributors and the curious.

## The big picture

A composite USB device with three interfaces, seven smart-card applets and
one storage layer. Day to day everything runs on one RP2350 core — the
second wakes only to parallelize RSA keygen (below):

```
 USB (embassy-usb, interrupt executor — always responsive)
 ├── FIDO HID (usage page 0xF1D0)  ── CTAPHID framing ──┐
 ├── CCID (smart-card, class 0x0B) ── APDU framing ─────┤
 └── boot keyboard (OTP typing)    ── feature reports ──┤
                                                        ▼
                worker task (thread executor — may block for seconds)
                ├── FIDO2/U2F applet            (rsk-fido)
                ├── OpenPGP card 3.4            (rsk-openpgp)
                ├── PIV                         (rsk-piv)
                ├── OATH                        (rsk-oath)
                ├── Yubico/Nitro OTP slots      (rsk-otp)
                ├── management (ykman)          (rsk-mgmt)
                ├── vendor + rescue             (firmware, rsk-rescue)
                ▼
                flash KV store (rsk-fs over sequential-storage)
```

**Two executors.** USB and the transports live on a high-priority
`InterruptExecutor`; the applet dispatch lives on the low-priority thread
executor in a single *worker* task that owns the flash and the TRNG outright.
Long synchronous work — on-card RSA generation, flash compaction, a touch
wait — blocks only the worker, while the interrupt executor keeps the bus
enumerated, streams CCID/CTAPHID keepalives, and animates the LED. No
mutexes: ownership does the synchronization.

**Why (mostly) one core:** the async executor gives the *concurrency* the
upstream design used a second core and hand-rolled queues for. Core 1 is
kept out of the transport picture and has exactly one job: during on-card
RSA generation both cores race the prime search — independent random
candidates, each core with its own DRBG stream, one shared two-prime pool
(`firmware/src/core1.rs`) — which roughly halves the expected keygen time.
Outside keygen it parks in WFE, and embassy-rp pauses it around every flash
erase/program, so its XIP fetches never collide with flash writes.

## Crates

| Crate | Contents |
|---|---|
| `firmware` | the only crate that touches the HAL: board bring-up, USB descriptors, executors, the worker, OTP fuse access, LED, BOOTSEL touch |
| `rsk-sdk` | APDU parsing (cases 1–4, short + extended), BER-TLV, status words, the `Applet` trait + dispatcher |
| `rsk-fs` | the flash filesystem: 16-bit file ids over two `sequential-storage` KV partitions (main + high-churn counters), ACLs, metadata records |
| `rsk-crypto` | one wrapper over RustCrypto: hashes, HMAC/HKDF, AES-CBC/CFB/GCM, ChaCha20-Poly1305, PIN KDFs, HMAC-DRBG, ML-DSA-44/ML-KEM, base64url, CRC |
| `rsk-usb` | the CTAPHID reassembler/framer and the CCID state machine, transport-agnostic and fully host-testable |
| `rsk-fido` | FIDO2 (CTAP 2.1) + U2F: credentials, clientPIN (protocols 1+2), credManagement, extensions (hmac-secret, credProtect, credBlob, largeBlobs, minPinLength), enterprise attestation, seed backup + soft-lock vendor commands |
| `rsk-openpgp` | OpenPGP card 3.4: DO model, PW1/RC/PW3, import/generate, PSO, AES PSO, certs — EC + RSA-2048/3072/4096 |
| `rsk-piv` | PIV: 24 key slots + F9 attestation, management-key auth, generate/import/sign/ECDH, on-card X.509 via a hand-rolled backward DER writer |
| `rsk-oath` | YKOATH protocol: TOTP/HOTP, touch-required accounts, access codes |
| `rsk-otp` | Yubico OTP slots ×4: CCID command surface + the keyboard frame protocol and typed-ticket generation |
| `rsk-mgmt` | the YubiKey management applet (DeviceInfo, interface toggles) served over both CCID and CTAPHID |
| `rsk-rescue` | recovery/provisioning applet: identity, phy config record, flash info, secure-boot status, attestation key, reboot, the one OTP-lock write |
| `rsk-rsa-asm` | vendored C/ARM-asm modular exponentiation behind one FFI fn (host build uses a pure-Rust fallback) |

Everything except `firmware` is hardware-agnostic and runs the full test
suite on the host ([testing.md](testing.md)).

## Flash layout

Two KV partitions at fixed offsets (`firmware/memory.x`): the main store, and
a small separate partition for the per-operation counters so their churn
never forces compaction of long-lived records. Files are 16-bit ids; each
applet owns disjoint ranges (FIDO `0x10xx/0xCxxx/0xCFxx/0xD0xx`, OpenPGP DO
mirrors, PIV `0xD1xx/0xD2xx`, OTP slots `0xBBxx`, phy/rescue `0xE0xx`) and a
reset wipes exactly its own predicate — never a range shared with another
applet.

Key sealing at rest: `kbase = HKDF(serial_hash, otp_master_key)` keys
AES-CBC for the FIDO seed (tagged formats: plain vs OTP-rooted generation)
and AES-GCM for PIV keys; OpenPGP keys sit under the PIN-wrapped DEK chain.
When the OTP master key gets provisioned later in a device's life, a boot
pass and lazy PIN-verify hooks migrate every sealed object to the new root
without losing data.

## Device identity

USB VID/PID, product strings and the reported firmware version are
compile-time knobs ([build.md](build.md)) with a YubiKey-5 default so the
Yubico ecosystem tools work. A flash-resident *phy* record can override
VID/PID and the product string at boot (the store mounts before the USB
builder runs for exactly this reason). FIDO tools find the device by HID
usage page, CCID tools by the reader name.

## User presence

One BOOTSEL button, shared by all applets through a `UserPresence` trait the
firmware implements once: FIDO operations, OpenPGP UIF, PIV touch policies,
OATH touch accounts, and OTP slot typing (1–4 presses select the slot) all
gate on it. The no-touch build (`--no-default-features`) auto-confirms — for
test rigs, not for daily use.

## Provenance

RS-Key reimplements the applet behaviour, file layouts and protocol surface
of [pico-keys](https://github.com/polhenarejos) (AGPL, see
[NOTICE](../NOTICE)) in Rust, replacing the C HAL/runtime/transport stack
with embassy and RustCrypto:

| was (C) | is (Rust) |
|---|---|
| pico-sdk runtime + TinyUSB | `embassy-rp` + `embassy-usb` |
| mbedTLS | RustCrypto (`p256/p384/p521/k256`, `rsa`, `ed25519-dalek`, …) |
| TinyCBOR | `minicbor` |
| bespoke wear-leveled flash writer | `sequential-storage` |
| core0/core1 + queues | one async executor pair; core1 = a keygen math engine only |

Where the two implementations deliberately differ (at-rest sealing, seed
PIN-wrapping, OTP provisioning policy, several upstream bugs not carried
over), the divergence is a documented design decision — see
[threat-model.md](threat-model.md) and the crate docs.
