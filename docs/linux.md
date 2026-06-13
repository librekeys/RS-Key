# Linux host setup

The board enumerates as a composite **FIDO HID + CCID** device under the
default YubiKey USB identity `0x1050:0x0407` (the default build; other presets:
[build.md](build.md)). The two transports have different host requirements on
Linux:

| Transport | Used by | Out of the box? |
|---|---|---|
| **FIDO HID** (`0xF1D0`) | WebAuthn, `ssh ed25519-sk`, `fido2-token`, python-fido2 | yes, once the yubico udev rules grant your user access to the hidraw node |
| **CCID** (PC/SC) | OpenPGP, PIV, OATH, Yubico-OTP, `ykman`, `gpg --card-status` | needs `pcscd` running **and** a polkit rule to use it as a non-root / SSH-session user |

```mermaid
flowchart LR
    subgraph fido["FIDO HID — usually works out of the box"]
      a["WebAuthn · ssh-sk · fido2-token"] --> b["hidraw + yubico udev rules"]
    end
    subgraph ccid["CCID (PC/SC) — needs two pieces"]
      c["ykman · gpg · OpenPGP / PIV / OATH"] --> d["pcscd + polkit rule<br/>(+ disable-ccid for gpg)"]
    end
```

FIDO generally works after installing the standard yubico udev rules. CCID is
the part that needs the extra two pieces below: a **polkit rule** (so a
non-root user — including one over SSH — may talk to `pcscd`) and, if you also
use GnuPG, **`disable-ccid`** in `scdaemon.conf` so `gpg`'s `scdaemon` goes
through `pcscd` instead of grabbing the raw CCID interface and locking out
`ykman`/`pcsc-tools`.

> Verified on a **NixOS 25.11** host (kernel 6.18.x): FIDO `getInfo` and
> `ykman info` work as a plain user over SSH once the polkit rule below is in
> place; `gpg --card-status` works with `disable-ccid`.

Replace `youruser` with your login name throughout.

## NixOS (declarative)

Add to your `configuration.nix`:

```nix
{ pkgs, ... }:
{
  # PC/SC daemon for the CCID applets (OpenPGP / PIV / OATH / OTP).
  services.pcscd.enable = true;

  # udev rules that grant access to the FIDO hidraw node and the YubiKey
  # interfaces. The stock yubico rules already match our 0x1050:0x0407
  # identity, so no custom rule is needed.
  services.udev.packages = [
    pkgs.yubikey-personalization
    pkgs.libfido2
  ];

  # Let a non-root user (e.g. over SSH) talk to pcscd. Without this, CCID works
  # only as root and `ykman`/`gpg --card-status` fail from an SSH session.
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
           action.id == "org.debian.pcsc-lite.access_card") &&
          subject.user == "youruser") {
        return polkit.Result.YES;
      }
    });
  '';

  # Optional: the host tools (ykman, gpg, openssh with FIDO support).
  environment.systemPackages = with pkgs; [
    yubikey-manager   # ykman
    libfido2          # fido2-token, fido2-assert
    opensc            # opensc-tool -l, pkcs11
    pcsctools         # pcsc_scan
  ];
}
```

`nixos-rebuild switch`, then re-plug the board (or restart `pcscd`).

## Generic Linux (Debian / Ubuntu / Fedora / Arch)

1. **Install the stack** — package names vary by distro:
   - Debian/Ubuntu: `pcscd pcsc-tools libfido2-1 yubikey-manager opensc`
   - Fedora: `pcsc-lite pcsc-tools libfido2 yubikey-manager opensc`
   - Arch: `pcsclite ccid yubikey-manager libfido2 opensc`

2. **Enable pcscd:** `sudo systemctl enable --now pcscd.socket`

3. **udev rules** for FIDO + YubiKey access usually ship with `libfido2` /
   `yubikey-personalization` / `libu2f-host`. If your user still can't open the
   device, confirm the rules are installed under `/usr/lib/udev/rules.d/`
   (e.g. `70-u2f.rules`) and that you're in the right group (`plugdev` on
   Debian/Ubuntu), then `sudo udevadm control --reload && sudo udevadm trigger`.

4. **polkit rule** for non-root pcscd access — create
   `/etc/polkit-1/rules.d/41-pcsc-rsk.rules`:

   ```javascript
   polkit.addRule(function(action, subject) {
     if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
          action.id == "org.debian.pcsc-lite.access_card") &&
         subject.user == "youruser") {
       return polkit.Result.YES;
     }
   });
   ```

   (Use `subject.isInGroup("plugdev")` instead of `subject.user == …` to grant
   a whole group.) Restart polkit/pcscd or re-plug afterwards.

## GnuPG (`gpg --card-status`, OpenPGP)

`scdaemon` defaults to grabbing the CCID interface directly, which fights
`pcscd` and locks out `ykman`/`pcsc_scan`. Route it through `pcscd` instead by
adding to `~/.gnupg/scdaemon.conf`:

```
disable-ccid
pcsc-shared
```

Then reload it: `gpgconf --kill scdaemon`. After this, `gpg --card-status` and
`ykman`/`pcsc_scan` coexist (they share the one reader through `pcscd`).

## FIDO / SSH (`ed25519-sk`)

Once the udev rules are in place, OpenSSH with libfido2 support works directly —
no pcscd involved (FIDO is HID, not CCID):

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk   # enroll (touch + PIN)
ssh -i ~/.ssh/id_ed25519_sk youruser@host          # login (one touch)
```

The key file is a handle, copyable between machines. Use lowercase `-i` (not
`-I`, which is PKCS#11). Most distro OpenSSH builds already link libfido2; if
`ssh-keygen` reports "no FIDO SecurityKeyProvider", install `libfido2` and point
`SSH_SK_PROVIDER` / `SecurityKeyProvider` at `libsk-libfido2.so`.

## Going further (NixOS quality-of-life)

Because the device presents as a YubiKey (`0x1050:0x0407`), the usual
YubiKey-on-NixOS recipes apply unchanged — PAM U2F for `sudo`/login, LUKS
FIDO2 unlock, gpg-agent SSH. A good walkthrough:
[Improving QoL on NixOS with a YubiKey](https://unmovedcentre.com/posts/improving-qol-on-nixos-with-yubikey/) —
substitute this device wherever it says YubiKey.

## Troubleshooting

- **`ykman`/`pcsc_scan` says no reader, or "Failed to connect":** `scdaemon`
  (from a prior `gpg`) is holding the reader exclusively. `gpgconf --kill
  scdaemon`, then retry. The `disable-ccid` + `pcsc-shared` config above
  prevents the recurrence.
- **`ykman info` connects but shows firmware `3.0.0 / U2F` only:** `ykman`
  derives the device from the **PC/SC reader name**, which must contain
  `YubiKey`. Our firmware names the reader `Yubico YubiKey RSK OTP+FIDO+CCID`,
  so this works; if you changed the product string, restore a name containing
  `Yubico`/`YubiKey` (see [build.md](build.md)).
- **Everything hangs after heavy USB debugging:** the `pcscd` + `scdaemon` +
  kernel USB stack can wedge in a way that surviving `pcscd`/`scdaemon`
  restarts or a re-plug do **not** clear — a **full host reboot** does. This is
  a host-stack quirk, not a firmware issue.
- **Verify the reader:** `pcsc_scan` (or `opensc-tool -l`) should list
  `Yubico YubiKey RSK OTP+FIDO+CCID`; `ykman info` should report `5.7.4` with
  all six applications enabled.
