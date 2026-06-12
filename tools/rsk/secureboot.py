# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk secure-boot — secure-boot provisioning (host picotool ritual).

Staged so every irreversible write is proven by a real boot before the next, and
the only bricking step is the single SECURE_BOOT_ENABLE bit:

  status    read the current secure-boot OTP state (always safe)
  load-key  A: bootkey0 fingerprint + KEY_VALID (slot 0).      non-enforcing
  harden    B: DEBUG_DISABLE + GLITCH_DETECTOR_ENABLE/SENS=3.   non-enforcing
  enable    C: SECURE_BOOT_ENABLE = 1.                          the brick bit
  lock      D: KEY_INVALID=0xE + PAGE1/PAGE2 bootloader-read-only.

Optional stage 3 (anti-rollback, docs/production.md) lives in `rsk otp
rollback-require` — it burns from the *firmware* side, so it works before and
after `lock`; `status` here shows ROLLBACK_REQUIRED + the boot-version
thermometer either way.

USB BOOTSEL stays enabled (the recovery path); the signing key lives outside the
repo and must be backed up. Run against a board in BOOTSEL. --dry-run prints the
exact picotool commands without touching anything.
"""
import json
import os
import re
import tempfile

from .common import confirm, die, picotool

CRIT1_ROW, BOOT_FLAGS1_ROW, BOOTKEY0_0_ROW = 0x40, 0x4B, 0x80
PAGE1_LOCK1_ROW, PAGE2_LOCK1_ROW = 0xF83, 0xF85
KEY_INVALID_UNUSED = 0xE
# Anti-rollback: BOOT_FLAGS0 bit 11 + the 48-bit DEFAULT_BOOT_VERSION
# thermometer. All RBIT-3 (three consecutive row copies, bitwise majority).
BOOT_FLAGS0_ROW, BOOT_VERSION0_ROW, BOOT_VERSION1_ROW = 0x48, 0x4E, 0x51
ROLLBACK_REQUIRED_BIT = 1 << 11
# PAGEx_LOCK1 byte = LOCK_BL[5:4] | LOCK_NS[3:2] | LOCK_S[1:0], x3 majority.
# 0x14 = BL/NS read-only, S read-write — NOT 0x3C (inaccessible): pages 1 & 2
# hold the flags + boot-key the bootrom must READ at every boot.
PAGE_LOCK_BL_RO = 0x141414


def register(sub):
    p = sub.add_parser("secure-boot", help="secure-boot provisioning (IRREVERSIBLE)")
    g = p.add_subparsers(dest="cmd", required=True)
    g.add_parser("status", help="read the current secure-boot OTP state").set_defaults(func=cmd_status)
    lk = g.add_parser("load-key", help="A: bootkey fingerprint + KEY_VALID")
    lk.add_argument("otp_json", help="the otp.json that `picotool seal` produced")
    lk.add_argument("--dry-run", action="store_true")
    lk.set_defaults(func=cmd_load_key)
    for name, fn in (("harden", cmd_harden), ("enable", cmd_enable), ("lock", cmd_lock)):
        sp = g.add_parser(name, help=f"{name} stage")
        sp.add_argument("--dry-run", action="store_true")
        sp.set_defaults(func=fn)


def require_bootsel():
    r = picotool("info", check=False)
    if r.returncode != 0 or "RP2350" not in r.stdout:
        die("no RP-series device in BOOTSEL mode (reboot first: `rsk reboot bootsel`)")


def _raw(row):
    r = picotool("otp", "get", "-r", "-n", f"{row:#x}", check=False)
    if r.returncode != 0:
        return None
    m = re.search(r"VALUE\s+(0x[0-9a-fA-F]+)", r.stdout)
    return int(m.group(1), 16) & 0xFFFFFF if m else None


def _majority3(row):
    """Bitwise 2-of-3 majority over an RBIT-3 row triple — the bootrom's view."""
    a, b, c = ((_raw(row + i) or 0) for i in range(3))
    return (a & b) | (a & c) | (b & c)


def read_state():
    crit1, flags1 = _raw(CRIT1_ROW) or 0, _raw(BOOT_FLAGS1_ROW) or 0
    version = (bin(_majority3(BOOT_VERSION0_ROW)).count("1")
               + bin(_majority3(BOOT_VERSION1_ROW)).count("1"))
    return {
        "secure_boot_enable": bool(crit1 & 1), "debug_disable": bool(crit1 & (1 << 2)),
        "glitch_enable": bool(crit1 & (1 << 4)), "glitch_sens": (crit1 >> 5) & 3,
        "key_valid": flags1 & 0xF, "key_invalid": (flags1 >> 8) & 0xF,
        "bootkey0_present": any((_raw(BOOTKEY0_0_ROW + i) or 0) for i in range(2)),
        "page1_lock": _raw(PAGE1_LOCK1_ROW), "page2_lock": _raw(PAGE2_LOCK1_ROW),
        "rollback_required": bool(_majority3(BOOT_FLAGS0_ROW) & ROLLBACK_REQUIRED_BIT),
        "boot_version": version,
    }


def print_state(s):
    locked = (s["secure_boot_enable"] and s["key_invalid"] == KEY_INVALID_UNUSED
              and s["debug_disable"] and s["glitch_enable"] and s["glitch_sens"] == 3)
    print(f"  bootkey present : {s['bootkey0_present']}")
    print(f"  KEY_VALID/INVALID : {s['key_valid']:#x} / {s['key_invalid']:#x}")
    print(f"  DEBUG_DISABLE   : {s['debug_disable']}")
    print(f"  GLITCH enable/sens: {s['glitch_enable']} / {s['glitch_sens']}")
    print(f"  SECURE_BOOT_ENABLE: {s['secure_boot_enable']}   <-- enforcement")
    print(f"  ROLLBACK_REQUIRED : {s['rollback_required']}   boot version {s['boot_version']}/48")
    print(f"  => secure boot {'LOCKED' if locked else 'ENABLED' if s['secure_boot_enable'] else 'NOT enabled'}")


def _set(args, dry):
    print("   picotool otp", *args)
    if not dry:
        picotool("otp", *args)


def cmd_status(args):
    require_bootsel()
    print("Secure-boot OTP state:")
    print_state(read_state())


def cmd_load_key(args):
    otp_json = os.path.expanduser(args.otp_json)
    if not os.path.exists(otp_json):
        die(f"{otp_json} not found (the otp.json `picotool seal` produced)")
    require_bootsel()
    s = read_state()
    if s["bootkey0_present"] or s["key_valid"]:
        die("a bootkey / KEY_VALID is already present — stage A already done.")
    with open(otp_json) as f:
        data = json.load(f)
    data.pop("crit1", None)  # stage A must NOT enable enforcement
    if "bootkey0" not in data or "boot_flags1" not in data:
        die(f"{otp_json} is missing bootkey0/boot_flags1 — not a seal otp.json?")
    print(f"Stage A — bootkey {bytes(data['bootkey0']).hex()} + KEY_VALID (non-enforcing):")
    confirm("LOAD-BOOTKEY") if not args.dry_run else None
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "bootkey_only.json")
        with open(p, "w") as f:
            json.dump(data, f)
        print("   picotool otp load", p)
        if not args.dry_run:
            picotool("otp", "load", p)
            s = read_state()
            if not s["bootkey0_present"] or not (s["key_valid"] & 1):
                die("verify failed: bootkey0/KEY_VALID not set")
            print_state(s)
    print("\nNEXT: reflash the SIGNED UF2, confirm it boots, then `rsk secure-boot harden`")


def cmd_harden(args):
    require_bootsel()
    if not read_state()["bootkey0_present"]:
        die("no bootkey present — run `load-key` first.")
    print("Stage B — DEBUG_DISABLE + GLITCH_DETECTOR (non-enforcing; kills SWD — fine, BOOTSEL-only):")
    confirm("HARDEN-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_CRIT1.DEBUG_DISABLE", "1"], args.dry_run)
    _set(["set", "OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE", "1"], args.dry_run)
    _set(["set", "OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS", "3"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if not (s["debug_disable"] and s["glitch_enable"] and s["glitch_sens"] == 3):
            die("verify failed: hardening fuses did not take")
        print_state(s)
    print("\nNEXT: reboot, confirm the board still boots, then `rsk secure-boot enable`")


def cmd_enable(args):
    require_bootsel()
    s = read_state()
    if not s["bootkey0_present"]:
        die("no bootkey — run `load-key`/`harden` first.")
    if s["secure_boot_enable"]:
        die("SECURE_BOOT_ENABLE already set.")
    print("Stage C — SECURE_BOOT_ENABLE = 1. THE IRREVERSIBLE ENFORCEMENT BIT.")
    print("Make sure a SIGNED image is flashed and was proven to boot.")
    confirm("ENABLE-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_CRIT1.SECURE_BOOT_ENABLE", "1"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if not s["secure_boot_enable"]:
            die("verify failed: SECURE_BOOT_ENABLE did not take")
        print_state(s)
    print("\nNEXT: prove signed boots; negative-test an UNSIGNED UF2 is rejected; then `lock`")


def cmd_lock(args):
    require_bootsel()
    if not read_state()["secure_boot_enable"]:
        die("SECURE_BOOT_ENABLE not set — run `enable` and verify it first.")
    print("Stage D — KEY_INVALID=0xE (revoke 3 unused slots) + PAGE1/PAGE2 read-only:")
    confirm("LOCK-SECURE-BOOT") if not args.dry_run else None
    _set(["set", "OTP_DATA_BOOT_FLAGS1.KEY_INVALID", f"{KEY_INVALID_UNUSED:#x}"], args.dry_run)
    _set(["set", "-r", "OTP_DATA_PAGE1_LOCK1", f"{PAGE_LOCK_BL_RO:#x}"], args.dry_run)
    _set(["set", "-r", "OTP_DATA_PAGE2_LOCK1", f"{PAGE_LOCK_BL_RO:#x}"], args.dry_run)
    if not args.dry_run:
        s = read_state()
        if s["key_invalid"] != KEY_INVALID_UNUSED:
            die("verify failed: KEY_INVALID did not take")
        print_state(s)
    print("\nDONE. Every future reflash must be a `picotool seal --sign`-ed UF2. Back up the key.")
    print("Optional next: anti-rollback — seal with `--rollback`, then `rsk otp rollback-require`")
    print("(docs/production.md, stage 3).")
