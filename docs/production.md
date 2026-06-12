# Production setup — signed boot + OTP master key

> ⚠️ **EXPERIMENTAL — IRREVERSIBLE — BRICK RISK.**
> Everything on this page burns one-time-programmable fuses or changes what
> the chip will ever boot again. A mistake can permanently brick the board or
> permanently lose your enrolled credentials. Read the whole page before
> running anything. The tools refuse to act without typed confirmations and
> support `--dry-run` — use it.

Out of the box, RS-Key's at-rest encryption roots in a key derived on the
device and stored sealed in flash. That stops casual key extraction, but a
sufficiently motivated attacker who steals the board can dump flash over
BOOTSEL and grind offline. The production path closes that, in two
independent stages:

1. **OTP master key (MKEK)** — fuse a random 32-byte key into RP2350 OTP
   page 58 and re-root all at-rest sealing in it, then hard-lock the page so
   neither BOOTSEL nor non-secure code can ever read it. A flash dump alone
   is now worthless.
2. **Secure boot** — fuse your public-key fingerprint and the
   `SECURE_BOOT_ENABLE` bit so the bootrom runs *only* images you signed.
   Attacker-flashed firmware (the remaining way to read the OTP key) no
   longer runs.

A third, optional stage builds on those: **anti-rollback**, so that *old*
images you signed — with bugs you have since fixed — stop booting too.

Each stage is usable alone; together they are the full story. All are driven
from the host — the firmware never burns a fuse behind your back. The two
exceptions are rows that physically cannot be written from BOOTSEL
(bootloader-read-only OTP pages): the page-58 *lock* and the
`ROLLBACK_REQUIRED` flag, each applied by the firmware on explicit command.

## Stage 1 — OTP master key

What it does: writes a random DEVK (device attestation key) and MKEK (master
sealing key) plus anti-imaging chaff into OTP page 58, ECC-verified, then
locks the page. On the next boot the firmware notices the provisioned key and
**migrates everything already on the device** — FIDO seed, PIV keys, OpenPGP
key wraps, PIN verifiers — under the new root. Your enrolled credentials
survive; that is the point of the migration layer.

```sh
rsk reboot bootsel               # picotool needs the chip in BOOTSEL
rsk otp burn --dry-run           # preview every step
rsk otp burn                     # typed confirmation; keys are generated and FORGOTTEN
picotool reboot -a               # back to the app; migration runs at boot
rsk otp lock-page58              # firmware applies the page-58 hard lock (typed confirm)
```

Facts to internalize first:

- The burn tool generates MKEK/DEVK randomly and **forgets them** — there is
  no copy to lose, and none to back up. The fuses *are* the key.
- After the burn, the **device attestation public key changes** (it now
  derives from the fused DEVK). FIDO/PIV identities survive; the rescue
  attestation key does not — expected, not data loss.
- After `lock-page58`, `picotool otp get` on page 58 fails with a permission
  error forever. Only the secure-mode firmware can read the keys.
- A seed backup (`rsk backup`) made before or after is unaffected — backups
  carry the seed value, which gets re-sealed under whatever root the device
  has.

## Stage 2 — secure boot

What it does: the RP2350 bootrom verifies an ECDSA (secp256k1 + SHA-256)
signature on every image against a fingerprint fused into OTP. Unsigned or
foreign-signed images do not boot — the chip falls back to BOOTSEL, where you
can always drag a correctly-signed UF2 (recovery path).

**The permanent consequences:**

- **Every future flash must be signed with your key.** The dev loop becomes
  build → `picotool seal --sign` → flash.
- **Losing the signing key bricks the board for new firmware** (the current
  signed image keeps booting). Back the key up before enabling enforcement.
- `DEBUG_DISABLE` is burned along the way — SWD is gone (flashing is BOOTSEL
  anyway).

### 2a. Generate a signing key (once, off-repo)

```sh
mkdir -p ~/.rs-key-secrets && cd ~/.rs-key-secrets
openssl ecparam -genkey -name secp256k1 -noout -out secure_boot_key.pem
openssl ec -in secure_boot_key.pem -pubout -out secure_boot_pub.pem
chmod 600 secure_boot_key.pem
# BACK IT UP somewhere that survives this machine.
```

### 2b. Sign and prove a signed image boots (before any fuse)

```sh
picotool seal --sign --hash firmware.uf2 firmware-signed.uf2 \
    ~/.rs-key-secrets/secure_boot_key.pem ~/.rs-key-secrets/otp_secureboot.json \
    --major 1 --minor 0 --rollback 1
picotool info firmware-signed.uf2        # must say "signature: verified"
# flash firmware-signed.uf2 over BOOTSEL and confirm the device works
```

(`--rollback 1` stamps the current anti-rollback epoch into the image — see
[Stage 3](#stage-3--anti-rollback-optional); harmless before that stage, and
having it in every sealed image from day one is what makes the stage cheap.)

`seal` writes `otp_secureboot.json` (the boot-key fingerprint) next to the
key. The firmware's image definition is already secure-boot compatible; the
sealed UF2 carries the signature block.

### 2c. Burn, staged

`rsk secure-boot` splits provisioning so every irreversible write is proven
by a real boot before the next, and the only true point of no return is one
bit:

```sh
rsk secure-boot status      # read the current fuse state any time
rsk secure-boot load-key    # 1. boot-key fingerprint + KEY_VALID   (non-enforcing)
rsk secure-boot harden      # 2. DEBUG_DISABLE + glitch detectors   (non-enforcing)
rsk secure-boot enable      # 3. SECURE_BOOT_ENABLE = 1  ← the brick bit
rsk secure-boot lock        # 4. revoke unused key slots + lock the fuse pages
```

Each step has `--dry-run` and a typed confirmation. Between steps, reboot and
confirm the device still works. After `enable`, verify the negative case:
drag an *unsigned* UF2 — the bootrom must reject it and fall back to BOOTSEL;
re-drag the signed one to recover.

### The new flash workflow (forever)

```sh
cargo build --release -p firmware
picotool uf2 convert target/thumbv8m.main-none-eabihf/release/firmware -t elf firmware.uf2
picotool seal --sign --hash firmware.uf2 firmware-signed.uf2 \
    ~/.rs-key-secrets/secure_boot_key.pem ~/.rs-key-secrets/otp_secureboot.json \
    --major 1 --minor 0 --rollback 1
# flash firmware-signed.uf2 (BOOTSEL, or: rsk reboot bootsel && cp)
```

## Stage 3 — anti-rollback (optional)

With secure boot on, the bootrom refuses *foreign* images — but every image
you ever signed stays valid forever. The first time a release fixes a
security bug, that becomes a hole: an attacker with the device drags your
*previous* signed UF2 over BOOTSEL and attacks the bug you already fixed.
Anti-rollback closes it with two pieces, both native to the RP2350 bootrom:

- An **epoch** (rollback version) inside the signed image — the
  `--rollback N` in the seal commands above — checked against a 48-step
  thermometer counter in OTP (`DEFAULT_BOOT_VERSION`, advanced by the
  bootrom itself when a higher-epoch image boots). Images below the counter
  are refused.
- The **`ROLLBACK_REQUIRED` fuse** (BOOT_FLAGS0 bit 11). Without it an image
  carrying *no* epoch — every UF2 sealed before this feature — still boots,
  and the check above has no teeth. This fuse is the enforcement.

The fuse pages being bootloader-read-only after `lock` blocks neither part:
the bootrom advances the thermometer from the secure boot path, and the
fuse is burned by the firmware (`rsk otp rollback-require`) — the same
secure-side arrangement as the page-58 lock.

### Epoch policy

The thermometer has **48 steps for the board's life**, so an epoch is not a
release: bump it **only when a release fixes something an attacker would
gain by booting the previous image**, never for features. History:

| epoch | first build       | why                       |
|------:|-------------------|---------------------------|
| 1     | bcdDevice 0x074A  | anti-rollback introduced  |

Every signed artifact must carry the **current** epoch — firmware *and*
[rsk-wipe](../rsk-wipe/README.md) alike (sign the wipe at the current epoch,
never higher: booting a higher-epoch image advances the counter and orphans
everything below it).

### Enabling it (fresh and already-locked boards, same path)

1. Seal and flash firmware with `--rollback 1` (the workflow above), reboot,
   and confirm `rsk secure-boot status` reports `boot version 1/48`. If it
   still reads `0/48`, stop and investigate before going further — never
   burn the fuse on an unproven setup.
2. Re-seal `rsk-wipe` with the same `--rollback 1` — the recovery escape
   hatch must stay bootable.
3. From the running firmware: `rsk otp rollback-require` (typed
   confirmation; `--dry-run` reports state without burning). The firmware
   refuses unless secure boot is enabled — which also means the command can
   only run from an image that itself passed the rollback check, so the
   "fuse before versioned image" footgun cannot happen.
4. Negative-test: drag any *versionless* signed UF2 (e.g. the previous
   `firmware-signed.uf2`) — the bootrom must refuse it and fall back to
   BOOTSEL; re-drag the current image to recover.

### What changes forever

- Every future `picotool seal` **must** include `--rollback <current
  epoch>`. A versionless sealed image no longer boots — fail-closed, you
  find out at flash time, recover by re-sealing.
- A board that has seen epoch N never boots an epoch < N image again. There
  is no undo; do not bump epochs casually.

## Deliberate choices

- **USB BOOTSEL stays enabled.** It is the only reflash and the only recovery
  path (no debugger), it cannot bypass signature enforcement, and after the
  page-58 lock it cannot read the OTP keys. Disabling it (the datasheet's
  full checklist) would turn every bad flash into a permanent brick.
- **No image encryption.** The code is open source — there is nothing secret
  in the image (secrets live sealed in flash, rooted in OTP). The RP2350 also
  has no transparent XIP decryption; encrypted boot requires fitting the
  image in SRAM, which a ~1.7 MB image does not.

## Residual risks (still open after all stages)

- **XIP TOCTOU:** the image executes from external QSPI flash; hardware that
  swaps or emulates the flash chip between the bootrom's signature check and
  execution can subvert it. Decap/side-channel-class attack, out of scope.
- A host compromised while the device is plugged in can drive normal
  operations (as with any security key); see
  [threat-model.md](threat-model.md).
