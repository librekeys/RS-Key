# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk audit — read and verify the device's tamper-evident audit journal.

The firmware keeps a 128-entry flash ring of security events (boots, FIDO
operations, PIN changes/lockouts, config changes, backup/lock activity),
hash-chained from an "epoch" accumulator that absorbs evicted history. The
device signs the chain head with an ECDSA P-256 key derived from the OTP DEVK
(vendor AUDIT_CHECKPOINT), so the log is verifiable end-to-end:

  log     export and pretty-print the journal      (--pin if a PIN is set)
  verify  log + signed checkpoint over a fresh
          challenge; checks the chain and the
          signature                                 (touch; --pin if a PIN is set)

`verify --expect-key` additionally pins the attestation public key (hex,
65-byte SEC1) — record it once at provisioning time, then any later mismatch
means you are talking to a different (or cloned-without-OTP) device.
"""
import hashlib
import os
import sys

from .backup import _gated, _vendor
from .common import add_pin_arg, connect_fido, device_has_pin, die, resolve_pin

AUDIT_READ, AUDIT_CHECKPOINT = 7, 8
ENTRY_LEN = 20
CKPT_TAG = b"RSK-AUDIT-CKPT-v1"

EVENTS = {
    0x01: "BOOT",
    0x02: "MAKE_CREDENTIAL",
    0x03: "GET_ASSERTION",
    0x04: "RESET",
    0x05: "PIN_SET",
    0x06: "PIN_CHANGE",
    0x07: "PIN_LOCKOUT",
    0x08: "CFG_MIN_PIN",
    0x09: "CFG_ENTERPRISE_ATT",
    0x0A: "LOCK_ENGAGE",
    0x0B: "LOCK_RELEASE",
    0x0C: "BACKUP_EXPORT",
    0x0D: "BACKUP_LOAD",
    0x0E: "BACKUP_FINALIZE",
    0x0F: "U2F_REGISTER",
    0x10: "U2F_AUTH",
    0x11: "CHECKPOINT",
    0x12: "ATT_IMPORT",
    0x13: "ATT_CLEAR",
}


def register(sub):
    p = sub.add_parser("audit", help="tamper-evident audit journal")
    g = p.add_subparsers(dest="cmd", required=True)

    lg = g.add_parser("log", help="export and print the journal")
    add_pin_arg(lg)
    lg.set_defaults(func=cmd_log)

    v = g.add_parser("verify", help="log + DEVK-signed chain checkpoint (touch)")
    add_pin_arg(v)
    v.add_argument("--expect-key", help="pin the attestation pubkey (hex SEC1, from a prior verify)")
    v.set_defaults(func=cmd_verify)


def _fold(epoch, entries):
    h = epoch
    for off in range(0, len(entries), ENTRY_LEN):
        h = hashlib.sha256(h + entries[off:off + ENTRY_LEN]).digest()
    return h


def read_journal(dev, cid, pin):
    """AUDIT_READ → (start, seq_next, epoch, entries bytes)."""
    st, m = _vendor(dev, cid, _gated(AUDIT_READ, None, dev, cid, pin))
    if st == 0x36:
        die("device requires a PIN — pass --pin or enter it when prompted")
    if st != 0:
        die(f"audit read failed: {st:#x}")
    start, seq_next, epoch, entries = m[1], m[2], m[3], m[4]
    if len(entries) % ENTRY_LEN or len(entries) != (seq_next - start) * ENTRY_LEN:
        die("export length does not match the window — corrupt journal?")
    return start, seq_next, epoch, entries


def print_entries(entries):
    print(f"{'seq':>6}  {'uptime':>10}  {'event':<18} aux  detail")
    for off in range(0, len(entries), ENTRY_LEN):
        e = entries[off:off + ENTRY_LEN]
        seq = int.from_bytes(e[0:4], "little")
        t_ms = int.from_bytes(e[4:8], "little")
        name = EVENTS.get(e[8], f"0x{e[8]:02x}")
        detail = e[10:18].hex()
        print(f"{seq:>6}  {t_ms / 1000:>9.1f}s  {name:<18} {e[9]:>3}  {detail}")


def cmd_log(args):
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    start, seq_next, epoch, entries = read_journal(dev, cid, pin)
    print(f"window [{start}, {seq_next})  —  {seq_next - start} entries, "
          f"{start} folded into the epoch")
    print(f"epoch : {epoch.hex()}")
    print(f"head  : {_fold(epoch, entries).hex()}  (chain over the window — OK)\n")
    print_entries(entries)


def cmd_verify(args):
    dev, cid = connect_fido()
    pin = resolve_pin(args, has_pin=device_has_pin(dev, cid))
    start, seq_next, epoch, entries = read_journal(dev, cid, pin)
    head_local = _fold(epoch, entries)

    challenge = os.urandom(16)
    print("touch the device (BOOTSEL) to sign the checkpoint…", file=sys.stderr)
    st, m = _vendor(dev, cid,
                    _gated(AUDIT_CHECKPOINT, {1: challenge}, dev, cid, pin))
    if st == 0x30:
        die("checkpoint refused — no OTP DEVK provisioned (see docs/production.md)")
    if st == 0x27:
        die("denied — no touch within 30 s; press the button when the LED blinks")
    if st != 0:
        die(f"checkpoint failed: {st:#x}")
    head_signed, seq_signed, sig, pubkey = m[1], m[2], m[3], m[4]

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
    msg = CKPT_TAG + head_signed + seq_signed.to_bytes(4, "little") + challenge
    try:
        vk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        die("checkpoint SIGNATURE INVALID — do not trust this journal")

    if head_signed != head_local:
        die("signed head differs from the exported window — the journal changed "
            "between read and checkpoint; rerun, and if it persists: TAMPER")
    if args.expect_key and pubkey.hex() != args.expect_key.lower():
        die("attestation key MISMATCH — this is not the enrolled device")

    fp = hashlib.sha256(pubkey).hexdigest()[:16]
    print_entries(entries)
    print(f"\nchain   : OK — head {head_local.hex()}")
    print(f"sig     : OK — checkpoint over seq_next={seq_signed}, fresh challenge")
    print(f"att key : {pubkey.hex()}")
    print(f"          fingerprint {fp} — record this; pin later runs with --expect-key")
    print("verdict : journal authentic ✓")
