# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for rsk.common.resolve_pin — the one PIN-entry chokepoint.

Run from tools/:  python -m pytest rsk/test_common.py
Every gated command routes its PIN through resolve_pin, so the precedence
(flag > prompt), the PIN-free skip, and the required/non-TTY guards are the
behaviour the whole CLI's consistency rests on — pin them here. No device.
"""
import argparse

import pytest

from rsk import common


def _args(pin=None):
    return argparse.Namespace(pin=pin)


def _stub_tty(monkeypatch, *, tty=True, entered="hunter2"):
    """Force isatty() and capture/script the getpass prompt; returns the call log."""
    calls = []

    class _Stdin:
        def isatty(self):
            return tty

    def _getpass(prompt="FIDO2 PIN: "):
        calls.append(prompt)
        return entered

    monkeypatch.setattr(common.sys, "stdin", _Stdin())
    monkeypatch.setattr(common, "getpass", _getpass)
    return calls


def test_flag_wins_and_never_prompts(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="from-prompt")
    # --pin given: returned verbatim, the prompt is never reached…
    assert common.resolve_pin(_args("1234"), has_pin=True) == "1234"
    # …even when the device is PIN-free or a PIN is "required" (flag is explicit).
    assert common.resolve_pin(_args("1234"), has_pin=False, required=True) == "1234"
    assert calls == []


def test_pin_free_device_skips_the_prompt(monkeypatch):
    calls = _stub_tty(monkeypatch)
    assert common.resolve_pin(_args(), has_pin=False) is None
    assert calls == []  # a touch-only device is never asked for a PIN


def test_has_pin_prompts_interactively(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="s3cret")
    assert common.resolve_pin(_args(), has_pin=True) == "s3cret"
    assert len(calls) == 1


def test_unknown_has_pin_still_prompts_on_a_tty(monkeypatch):
    _stub_tty(monkeypatch, entered="abcd")
    assert common.resolve_pin(_args(), has_pin=None) == "abcd"


def test_custom_prompt_is_used(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="old")
    common.resolve_pin(_args(), has_pin=True, prompt="Current PIN: ")
    assert calls == ["Current PIN: "]


def test_empty_input_is_none(monkeypatch):
    _stub_tty(monkeypatch, entered="")
    assert common.resolve_pin(_args(), has_pin=True) is None


def test_required_dies_when_device_has_no_pin(monkeypatch):
    _stub_tty(monkeypatch)
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=False, required=True)


def test_required_dies_on_empty_input(monkeypatch):
    _stub_tty(monkeypatch, entered="")
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=True, required=True)


def test_non_tty_returns_none_without_prompting(monkeypatch):
    calls = _stub_tty(monkeypatch, tty=False)
    assert common.resolve_pin(_args(), has_pin=True) is None
    assert calls == []  # piped stdin: fall through to the device-side error path


def test_non_tty_required_dies(monkeypatch):
    _stub_tty(monkeypatch, tty=False)
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=True, required=True)
