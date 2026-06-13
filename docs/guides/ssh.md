# SSH with `ed25519-sk`

Hardware-backed SSH keys: the private key never leaves the device; logging
in takes one touch.

## Enroll

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk
# → touch the button twice; enter the FIDO PIN if one is set
ssh-copy-id -i ~/.ssh/id_ed25519_sk you@server
```

`ecdsa-sk` (P-256) works too if a server rejects ed25519-sk.

The generated `id_ed25519_sk` file is a **handle**, not a private key — it is
useless without the physical device. Copy it (and `.pub`) to any machine you
ssh from; the device is the factor.

## Log in

```sh
ssh -i ~/.ssh/id_ed25519_sk you@server      # one touch, no PIN
```

PIN is demanded at *enrollment* (credential creation is PIN-gated); plain
logins are user-presence only (one touch, no PIN). Want PIN-per-login?
Enroll with `ssh-keygen -t ed25519-sk -O verify-required`.

## macOS

Apple's system OpenSSH ships **without** FIDO support — `/usr/bin/ssh` fails
instantly with `Permission denied` before ever touching the device. Use
Homebrew OpenSSH:

```sh
brew install openssh
/opt/homebrew/opt/openssh/bin/ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk
/opt/homebrew/opt/openssh/bin/ssh -i ~/.ssh/id_ed25519_sk you@server
```

(or put `/opt/homebrew/opt/openssh/bin` ahead of `/usr/bin` in `PATH`, and
add an `IdentityFile` block to `~/.ssh/config` so plain `ssh host` works).

## Linux

Distro OpenSSH links libfido2 almost everywhere; you only need the udev
rules — see [linux.md](../linux.md). For login shells over SSH *to* the
machine with the device, nothing special: FIDO is local to where `ssh` runs.

## Resident SSH keys

`ssh-keygen -t ed25519-sk -O resident` stores the key on the device itself —
`ssh-keygen -K` downloads handles on any machine later (PIN required). Costs
one of the 256 resident slots; the non-resident default plus a
[seed backup](seed-backup.md) usually serves better: non-resident keys are
re-derivable from the seed, so a restored board keeps logging in with the
same key files.

## Troubleshooting

- `Permission denied` instantly on macOS → you're on `/usr/bin/ssh` (above).
- `enrollment: device not found` → FIDO udev rules missing
  ([linux.md](../linux.md)) or the browser/agent holds the device.
- Enrollment asks for a PIN you never set → some client builds require one;
  `rsk fido set-pin` and retry.
- After a factory FIDO reset, old `id_*_sk` files are dead (the seed they
  derive from is gone) — re-enroll, or restore the seed backup first.
