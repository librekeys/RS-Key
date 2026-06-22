# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk led — LED customisation over the vendor applet (CCID).

SET LED (INS 0x10, P1=brightness, P2 = color | steady 0x08 | status<<4,
optional data[0..1] = effect, speed) / GET LED (INS 0x11, returns
[steady, (effect, color, brightness, speed) x 4] — 17 bytes).
Per-status color + brightness + effect + speed; --steady is a solid color
(global). Persists in flash, applies live.
"""

from . import ccid

COLORS = {
    "off": 0,
    "red": 1,
    "green": 2,
    "blue": 3,
    "yellow": 4,
    "magenta": 5,
    "cyan": 6,
    "white": 7,
}
COLOR_NAMES = {v: k for k, v in COLORS.items()}
EFFECTS = {"legacy": 0, "vapor": 1, "bounce": 2, "flow": 3, "sparkle": 4}
EFFECT_NAMES = {v: k for k, v in EFFECTS.items()}
STATUSES = {"idle": 0, "processing": 1, "touch": 2, "boot": 3}
STATUS_NAMES = {v: k for k, v in STATUSES.items()}
P2_STEADY = 0x08
# 17-byte block format: [steady, (effect, color, brightness, speed) x 4]
BLOCK_STRIDE = 4  # bytes per status
BLOCK_OFF_STEADY = 0
BLOCK_OFF_EFFECT = 1  # first status starts here
BLOCK_OFF_COLOR = 2
BLOCK_OFF_BRIGHTNESS = 3
BLOCK_OFF_SPEED = 4


def register(sub):
    p = sub.add_parser("led", help="LED color/brightness/effect customisation")
    p.add_argument(
        "--status",
        choices=sorted(STATUSES),
        default="idle",
        help="which status to change (default idle)",
    )
    p.add_argument(
        "--brightness",
        type=int,
        metavar="0-255",
        help="per-channel brightness for --status (0 = off)",
    )
    p.add_argument("--color", choices=sorted(COLORS), help="color for --status")
    p.add_argument(
        "--effect", choices=sorted(EFFECTS), help="visual effect for --status"
    )
    p.add_argument(
        "--speed", type=int, metavar="0-255", help="effect speed (0 = built-in default)"
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--steady", action="store_true", help="solid color, no blinking")
    g.add_argument("--blink", action="store_true", help="restore status blinking")
    p.add_argument("--get", action="store_true", help="read the current config")
    p.set_defaults(func=run)


def _get_block(conn):
    d, s1, s2 = ccid.transmit(conn, [0x00, 0x11, 0x00, 0x00, 0x00])
    if (s1, s2) != (0x90, 0x00) or len(d) < 9:
        raise SystemExit(f"GET LED failed: {s1:02X}{s2:02X} (len {len(d)})")
    return d


def _status_offset(st):
    return BLOCK_OFF_EFFECT + st * BLOCK_STRIDE


def run(args):
    conn = ccid.connect()
    ccid.select(conn, ccid.VENDOR_AID)
    changing = (
        args.brightness is not None
        or args.color is not None
        or args.effect is not None
        or args.speed is not None
        or args.steady
        or args.blink
    )
    if changing:
        block = _get_block(conn)
        st = STATUSES[args.status]
        off = _status_offset(st)
        # Read current values from block.
        effect = block[off]
        color = block[off + 1]
        brightness = block[off + 2]
        steady = bool(block[BLOCK_OFF_STEADY])

        # Apply user overrides.
        if args.brightness is not None:
            if not 0 <= args.brightness <= 255:
                raise SystemExit("--brightness must be 0–255")
            brightness = args.brightness
        if args.color is not None:
            color = COLORS[args.color]
        if args.effect is not None:
            effect = EFFECTS[args.effect]
        if args.speed is not None:
            if not 0 <= args.speed <= 255:
                raise SystemExit("--speed must be 0–255")
        steady = True if args.steady else False if args.blink else steady

        # Build APDU: P1 = brightness, P2 = color | steady | status<<4.
        p2 = (color & 0x7) | (P2_STEADY if steady else 0) | (st << 4)
        # Include optional data bytes for effect and speed.
        data = []
        if args.effect is not None or args.speed is not None:
            data.append(effect)
            if args.speed is not None:
                data.append(args.speed & 0xFF)
        _, s1, s2 = ccid.transmit(conn, [0x00, 0x10, brightness & 0xFF, p2] + data)
        if (s1, s2) != (0x90, 0x00):
            raise SystemExit(f"SET LED failed: {s1:02X}{s2:02X}")
        parts = [
            f"set {args.status}: color={COLOR_NAMES.get(color, color)}",
            f"brightness={brightness}",
            f"effect={EFFECT_NAMES.get(effect, effect)}",
            f"(mode={'steady' if steady else 'blink'})",
        ]
        print(" ".join(parts))
    if args.get or not changing:
        d = _get_block(conn)
        print(f"mode={'steady' if d[BLOCK_OFF_STEADY] else 'blink'}")
        for st, name in sorted(STATUS_NAMES.items()):
            off = _status_offset(st)
            effect = EFFECT_NAMES.get(d[off], d[off])
            color = COLOR_NAMES.get(d[off + 1], d[off + 1])
            brightness = d[off + 2]
            print(
                f"  {name:<10} color={color:<8} brightness={brightness:<3}"
                f" effect={effect}"
            )
