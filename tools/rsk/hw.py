# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk hw — LED hardware wiring (data pin / driver / wire order) via the phy record.

The phy record (`EF_PHY`) is the device-config blob PicoForge also writes; it
survives every applet reset and is applied at boot. The rescue applet exposes it
as READ (INS 0x1E, P1=01) and WRITE (INS 0x1C, P1=01). This command does a
read-modify-write of ONLY the LED fields, so a USB identity / option set elsewhere
(PicoForge, a future `rsk` identity command) is preserved.

  --led-pin     the WS2812/gpio data GPIO (overrides the firmware build LED_PIN)
  --led-driver  the backend: gpio / pimoroni / ws2812 (overrides build LED_KIND)
  --led-order   the WS2812 wire byte order: rgb / grb (overrides build LED_ORDER)

A non-`none` firmware build compiles all three backends, so these switch the LED
at runtime — no reflash. The change applies at the NEXT boot, so a warm reboot is
issued unless --no-reboot. (Per-status COLOURS are a separate, live setting that
persists in a different record — see `rsk led`.)
"""

from . import ccid
from .status import RESCUE_AID

# phy TLV tags — must match crates/rsk-rescue/src/phy.rs.
TAG_LED_GPIO = 0x04
TAG_LED_DRIVER = 0x0C
TAG_LED_ORDER = 0x0D  # RS-Key vendor tag (PicoForge skips it as unknown)
TAG_LED_NUM = 0x0E  # RS-Key vendor tag: addressable LED count

# Driver numbering follows pico-fido / PicoForge's LedDriverType.
DRIVERS = {"gpio": 1, "pimoroni": 2, "ws2812": 3}
DRIVER_NAMES = {v: k for k, v in DRIVERS.items()}
ORDERS = {"rgb": 0, "grb": 1}
ORDER_NAMES = {v: k for k, v in ORDERS.items()}


def register(sub):
    p = sub.add_parser(
        "hw", help="LED hardware wiring (pin/driver/order) via the phy record"
    )
    p.add_argument(
        "--led-pin",
        type=int,
        metavar="0-29",
        help="WS2812/gpio data GPIO (RP2350A 0..=29)",
    )
    p.add_argument(
        "--led-driver",
        choices=sorted(DRIVERS),
        help="LED backend: gpio (on/off), pimoroni (3-pin PWM RGB), ws2812 (addressable)",
    )
    p.add_argument(
        "--led-order",
        choices=sorted(ORDERS),
        help="WS2812 wire byte order: grb (standard WS2812B) or rgb (Waveshare RP2350-One)",
    )
    p.add_argument(
        "--led-num",
        type=int,
        metavar="1-255",
        help="number of addressable LEDs connected (runtime, overrides MAX_LEDS)",
    )
    p.add_argument(
        "--get", action="store_true", help="read the current phy LED config and exit"
    )
    p.add_argument(
        "--no-reboot",
        action="store_true",
        help="don't reboot after writing (the change applies on the next boot)",
    )
    p.set_defaults(func=run)


def _parse_tlv(data):
    """Parse the phy record into an ordered list of (tag, value-bytes). A TLV
    running past the end ends the parse (mirrors the firmware parser)."""
    out, i = [], 0
    while i + 2 <= len(data):
        tag, ln = data[i], data[i + 1]
        i += 2
        if i + ln > len(data):
            break
        out.append((tag, data[i : i + ln]))
        i += ln
    return out


def _serialize_tlv(tlvs):
    out = bytearray()
    for tag, val in tlvs:
        out += bytes([tag, len(val)]) + bytes(val)
    return bytes(out)


def _upsert(tlvs, tag, value):
    """Set or replace a single-byte TLV in place; append if not present."""
    for idx, (t, _) in enumerate(tlvs):
        if t == tag:
            tlvs[idx] = (tag, bytes([value]))
            return
    tlvs.append((tag, bytes([value])))


def _read_phy(conn):
    d, s1, s2 = ccid.transmit(conn, [0x80, 0x1E, 0x01, 0x00, 0x00])
    if (s1, s2) != (0x90, 0x00):
        raise SystemExit(f"READ phy failed: {s1:02X}{s2:02X} (firmware too old?)")
    return _parse_tlv(d)


def _show(tlvs):
    by = {t: v for t, v in tlvs}
    pin = by.get(TAG_LED_GPIO)
    drv = by.get(TAG_LED_DRIVER)
    order = by.get(TAG_LED_ORDER)
    print(
        "phy LED config ('(build default)' = field absent, firmware build value used):"
    )
    print(f"  pin     {pin[0] if pin else '(build default)'}")
    print(f"  driver  {DRIVER_NAMES.get(drv[0], drv[0]) if drv else '(build default)'}")
    print(
        f"  order   {ORDER_NAMES.get(order[0], order[0]) if order else '(build default)'}"
    )
    led_num = by.get(TAG_LED_NUM)
    print(f"  num     {led_num[0] if led_num else '(build default)'}")


def run(args):
    conn = ccid.connect()
    _, s1, s2 = ccid.select(conn, RESCUE_AID)
    if (s1, s2) != (0x90, 0x00):
        raise SystemExit(
            f"SELECT rescue AID failed: {s1:02X}{s2:02X} (firmware too old?)"
        )
    tlvs = _read_phy(conn)

    setting = (
        args.led_pin is not None
        or args.led_driver is not None
        or args.led_order is not None
        or args.led_num is not None
    )
    if args.get or not setting:
        _show(tlvs)
        return

    if args.led_pin is not None:
        if not 0 <= args.led_pin <= 29:
            raise SystemExit("--led-pin must be 0–29 (RP2350A GPIOs)")
        _upsert(tlvs, TAG_LED_GPIO, args.led_pin)
    if args.led_driver is not None:
        _upsert(tlvs, TAG_LED_DRIVER, DRIVERS[args.led_driver])
    if args.led_order is not None:
        _upsert(tlvs, TAG_LED_ORDER, ORDERS[args.led_order])
    if args.led_num is not None:
        if not 1 <= args.led_num <= 255:
            raise SystemExit("--led-num must be 1–255")
        _upsert(tlvs, TAG_LED_NUM, args.led_num)

    blob = _serialize_tlv(tlvs)
    _, s1, s2 = ccid.transmit(
        conn, [0x80, 0x1C, 0x01, 0x00, len(blob)] + list(blob) + [0x00]
    )
    if (s1, s2) != (0x90, 0x00):
        raise SystemExit(f"WRITE phy failed: {s1:02X}{s2:02X}")
    print("phy LED config written ✓")
    _show(tlvs)
    if args.no_reboot:
        print("not rebooting — the change applies on the next boot.")
    else:
        print("rebooting to apply…")
        ccid.reboot(conn, bootsel=False)
