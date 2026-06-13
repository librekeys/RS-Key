# OTP slots — Yubico OTP, challenge-response, static passwords

Four programmable slots. Slots 1–2 are YubiKey-compatible and fully manageable
with `ykman otp`; slots 3–4 are two extra slots managed over CCID (e.g.
`nitropy` or raw APDUs — `ykman` doesn't know they exist).

The device is also a **USB keyboard**: pressing the button *types* the slot's
output wherever your cursor is.

```mermaid
flowchart LR
    press["button press"] --> kbd["USB HID keyboard"] --> types["types the slot output"]
    ykman["ykman otp"] --> c1["CCID"] --> s12["slots 1–2"]
    raw["nitropy / raw APDU"] --> c2["CCID"] --> s34["slots 3–4"]
```

## Slot selection by presses

| Presses | Slot |
|---|---|
| 1 (short) | 1 |
| 2 | 2 |
| 3 | 3 |
| 4 | 4 |

## Program a slot

```sh
ykman otp info                                  # what's where
ykman otp yubiotp 1 --generate-key --serial-public-id     # classic Yubico OTP
ykman otp chalresp 2 --generate --touch                   # HMAC-SHA1 challenge-response
ykman otp static 1 --generate --length 38                 # typed static password
ykman otp swap                                  # swap slots 1 and 2
ykman otp delete 2
```

## Challenge-response from software

```sh
ykman otp calculate 2 <hex-challenge>
```

is the classic KeePassXC / LUKS pattern (`--touch` slots wait for a press).
The keyboard interface answers the same protocol, so tools built for
YubiKeys (KeePassXC's "YubiKey challenge-response") work as-is.

## Yubico OTP validation

A Yubico-OTP slot types 44-modhex-character one-time passwords. Public
validation (YubiCloud) requires uploading the AES key to Yubico — possible,
but for self-hosted validation servers you keep the key. Slot config tools
print everything needed at programming time.

## Notes

- The keyboard interface is a third USB interface (boot-protocol keyboard);
  if your OS asks about a new keyboard at first plug, that's this. It can be
  disabled per-interface via the management applet (`ykman config usb`).
- Touch-triggered typing always requires the physical press; the
  challenge-response APDU path honours each slot's touch flag.
- OTP slot secrets are not covered by the [seed backup](seed-backup.md).
