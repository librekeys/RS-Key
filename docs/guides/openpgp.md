# OpenPGP card

A full OpenPGP card 3.4 over CCID: three key slots (signature, decryption,
authentication), works with stock GnuPG.

Prereqs: on Linux, `pcscd` + the `scdaemon.conf` lines from
[linux.md](../linux.md). Check the card is visible:

```sh
gpg --card-status            # reader: Yubico YubiKey RSK …, OpenPGP v3.4
```

## PINs

| | Default | Unlocks |
|---|---|---|
| User PIN (PW1) | `123456` | signing, decryption, authentication |
| Admin PIN (PW3) | `12345678` | key import/generation, card settings |
| Reset Code | unset | unblocking PW1 without PW3 |

Change them first:

```sh
gpg --card-edit
gpg/card> admin
gpg/card> passwd            # menu: change PIN / Admin PIN / set Reset Code
```

Three wrong PW3 attempts lock admin operations permanently (factory reset
required) — standard OpenPGP card behaviour.

## Generate keys on-card

```sh
gpg --card-edit
gpg/card> admin
gpg/card> key-attr           # choose per-slot: ECC (ed25519/cv25519, NIST,
                             # secp256k1) or RSA 2048/3072/4096
gpg/card> generate           # makes all three keys + a gpg keyring entry
```

On-card generation means the private keys never existed anywhere else —
and cannot be backed up; gpg's "make an off-card backup" prompt covers the
encryption key only if you say yes. RSA generation is slow on this hardware
(≈22 s for 2048, ≈35 s for 3072, ≈65 s for 4096 — the device streams
keepalives, gpg just waits); EC is instant.

## Or import existing keys

```sh
gpg --edit-key YOURKEY
gpg> keytocard               # per subkey: moves it to a slot
```

Importing keeps an off-card copy in your keyring until you delete it —
your call which way the trade-off goes.

## Daily use

```sh
gpg --sign / --decrypt …          # asks for PW1, then touches the card
gpg --export-ssh-key YOURKEY      # the AUT slot doubles as an SSH key
```

For SSH via gpg-agent: `enable-ssh-support` in `gpg-agent.conf`, add the
keygrip to `~/.gnupg/sshcontrol` — the standard recipe, nothing
device-specific.

**Touch policies (UIF):** per-slot, set from the card-edit `uif` commands —
when on, every use of that key additionally requires a button press.

## AES encryption (PSO)

The card also offers symmetric AES encrypt/decrypt with an on-card key
(`gpg-card`'s and some tooling expose it; most users never need it).

## Factory reset (OpenPGP only)

```sh
rsk openpgp reset      # or: gpg --card-edit → admin → factory-reset
```

Wipes the OpenPGP applet (keys, PINs, DOs) and nothing else — FIDO/PIV/OATH
survive.

## Troubleshooting

- `gpg: selecting card failed: No such device` → scdaemon vs pcscd fight;
  apply [linux.md](../linux.md)'s `disable-ccid`, then
  `gpgconf --kill scdaemon`.
- `ykman` stops seeing the device after gpg used it → same fix.
- Wrong-PIN counters: `gpg --card-status` shows `PIN retry counter: 3 0 3`.
- `ykman openpgp info` → `ERROR: Incorrect TLV length` on firmware **before
  `0x0759`**: the GET DATA `6E` reply was missing its constructed-DO wrapper,
  which ykman's strict parser requires (`gpg` tolerated it). Fixed in `0x0759`;
  flash it and re-run. See [interop.md](../interop.md#known-issues).
