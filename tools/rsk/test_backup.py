# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host-side MSE channel tests for rsk.backup (no device, no hidapi).

Run from tools/:  python -m pytest rsk/test_backup.py

A simulated "device" mirrors the firmware's MSE + EXPORT crypto — ECDH plus, when
the host offers an ML-KEM-768 encapsulation key, an encapsulate and the same
hybrid HKDF the firmware uses. This pins that rsk derives the very channel key the
device derives (so an exported seed decrypts), and that an ML-KEM-less host still
negotiates the classical P-256 channel. The ML-KEM byte-interop with the
firmware's RustCrypto implementation is pinned separately by rsk-crypto's
`mlkem_interop_kat`, so a green test here means host ⇄ firmware agree end to end.
"""
import os
import sys
import types

# The transport is fully mocked below, so stub `hid` before importing rsk.ctaphid
# (it sys.exits at import if hidapi is missing). The fake module is never used.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from rsk import backup
from rsk.backup import MSE_PQ_SALT

mlkem = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")


def _simulated_device(seed):
    """Return a fake ``backup._vendor`` that plays the firmware's MSE + EXPORT."""
    chan = {}

    def fake_vendor(dev, cid, fields):
        sub = fields[1]
        if sub == backup.VENDOR_MSE:
            host_cose = fields[2][1]
            hx = int.from_bytes(host_cose[-2], "big")
            hy = int.from_bytes(host_cose[-3], "big")
            host_pub = ec.EllipticCurvePublicNumbers(hx, hy, ec.SECP256R1()).public_key()
            dpriv = ec.generate_private_key(ec.SECP256R1())
            z = dpriv.exchange(ec.ECDH(), host_pub)
            dn = dpriv.public_key().public_numbers()
            dx, dy = dn.x.to_bytes(32, "big"), dn.y.to_bytes(32, "big")
            dev_pub = b"\x04" + dx + dy
            resp = {1: {-2: dx, -3: dy}}
            ek = fields[2].get(2)
            if ek is not None:  # host went hybrid → encapsulate and bind both secrets
                ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
                chan["key"] = HKDF(algorithm=hashes.SHA256(), length=32, salt=MSE_PQ_SALT,
                                   info=dev_pub + ct).derive(z + ss)
                resp[2] = ct
            else:
                chan["key"] = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"",
                                   info=dev_pub).derive(z)
            chan["aad"] = dev_pub
            return 0, resp
        if sub == backup.EXPORT:
            nonce = os.urandom(12)
            sealed = ChaCha20Poly1305(chan["key"]).encrypt(nonce, seed, chan["aad"])
            return 0, {1: nonce + sealed}
        raise AssertionError(f"unexpected subcommand {sub}")

    return fake_vendor


def test_hybrid_channel_roundtrips_seed(monkeypatch):
    # Host offers ML-KEM, device encapsulates: the hybrid key must match so the
    # seed sealed by the device decrypts here.
    seed = bytes(range(32))
    monkeypatch.setattr(backup, "_vendor", _simulated_device(seed))
    assert backup.read_seed(None, None, pin=None) == seed


def test_classical_fallback_when_host_has_no_mlkem(monkeypatch):
    # An ML-KEM-less host sends no encapsulation key; the device follows with the
    # classical channel and the seed still roundtrips.
    seed = bytes(range(1, 33))
    monkeypatch.setattr(backup, "_MLKEM_OK", False)
    monkeypatch.setattr(backup, "_vendor", _simulated_device(seed))
    assert backup.read_seed(None, None, pin=None) == seed
