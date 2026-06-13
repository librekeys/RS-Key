# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.secureboot (no device, no picotool).

Run from tools/:  python -m pytest rsk/test_secureboot.py
The slot-row math, json re-targeting, free-slot picking, and the revoke
"don't orphan the last key" guard are the brick-risk decisions — pin them here.
"""
import pytest

from rsk import secureboot as sb


def test_slot_key_rows():
    # BOOTKEY{n}_0 = 0x80 + n*0x10, per `picotool otp list`
    assert [sb.slot_key_row(n) for n in range(4)] == [0x80, 0x90, 0xA0, 0xB0]


def test_valid_slot_range():
    for n in range(sb.N_KEY_SLOTS):
        assert sb._valid_slot(n) == n
    for bad in (-1, sb.N_KEY_SLOTS, 99):
        with pytest.raises(SystemExit):
            sb._valid_slot(bad)


def test_build_slot_json_retargets_field_and_sets_valid():
    seal = {"bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}, "crit1": {}}
    out = sb._build_slot_json(seal, 1, new_key_valid=0b11)
    assert out == {"bootkey1": list(range(32)), "boot_flags1": {"key_valid": 0b11}}
    # crit1 (enforcement) and the slot-0 field are NOT carried over
    assert "crit1" not in out and "bootkey0" not in out


def test_build_slot_json_slot0_is_backward_compatible():
    seal = {"bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}, "crit1": {}}
    assert sb._build_slot_json(seal, 0, 1) == {
        "bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}}


def test_build_slot_json_missing_fingerprint_dies():
    with pytest.raises(SystemExit):
        sb._build_slot_json({"boot_flags1": {}}, 0, 1)


def test_next_free_slot_skips_present_valid_revoked():
    # slot 0 present+valid, slot 2 revoked -> first free is slot 1
    s = {"slots_present": [True, False, False, False], "key_valid": 0b0001, "key_invalid": 0b0100}
    assert sb._next_free_slot(s) == 1
    # everything used -> None (needs a fresh board)
    full = {"slots_present": [True] * 4, "key_valid": 0b1111, "key_invalid": 0}
    assert sb._next_free_slot(full) is None


def test_revoke_leaves_valid_guard():
    # slots 0 & 1 valid, none revoked: revoking 0 leaves slot 1 -> safe (non-zero)
    assert sb._revoke_leaves_valid(0b0011, 0, 0) == 0b0010
    # only slot 0 valid: revoking it leaves nothing -> 0 (would brick)
    assert sb._revoke_leaves_valid(0b0001, 0, 0) == 0
    # slots 0 & 1 valid but slot 1 already revoked: revoking 0 leaves nothing
    assert sb._revoke_leaves_valid(0b0011, 0b0010, 0) == 0


def test_pages_locked():
    assert sb.pages_locked({"page1_lock": sb.PAGE_LOCK_BL_RO, "page2_lock": None}) is True
    assert sb.pages_locked({"page1_lock": None, "page2_lock": sb.PAGE_LOCK_BL_RO}) is True
    assert sb.pages_locked({"page1_lock": None, "page2_lock": 0}) is False
