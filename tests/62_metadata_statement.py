#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Validate the self-published FIDO Metadata Statement against source + device.

    nix develop -c python tests/62_metadata_statement.py

This is a drift guard for `metadata/rs-key.metadata.json`. It is NOT in the
main hardware gate (run it by hand, like the pair/secure-boot scripts).

Part A (host-only, always runs):
  * required MDS3 statement fields present;
  * `aaguid` (dashed) == the firmware `AAGUID` const in rsk-fido/consts.rs
    == the dashless `authenticatorGetInfo.aaguid`;
  * surrogate-only invariant: attestationTypes == ["basic_surrogate"] implies
    attestationRootCertificates == [];
  * `authenticationAlgorithms` (FIDO Registry strings) map exactly onto the
    classic COSE ids in `authenticatorGetInfo.algorithms`;
  * `authenticatorVersion` == `authenticatorGetInfo.firmwareVersion`.

Part B (runs only if a FIDO HID device is plugged in):
  * decodes the live `authenticatorGetInfo` and asserts it equals the embedded
    one, IGNORING the stateful fields (options.ep / options.clientPin /
    forcePINChange / minPINLength) which depend on PIN/enterprise state.

The statement describes the DEFAULT build profile. `advertise-pqc` adds COSE
-48 to algorithms and `fips-profile` drops -47 and raises minPINLength — if the
live device is one of those, Part B says so instead of failing blindly.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
META = os.path.join(ROOT, "metadata", "rs-key.metadata.json")
CONSTS = os.path.join(ROOT, "crates", "rsk-fido", "src", "consts.rs")

# FIDO Registry (v2.2) sign-algorithm string <-> COSE alg id, classic set only.
ALG_STR_TO_COSE = {
    "secp256r1_ecdsa_sha256_raw": -7,
    "ed25519_eddsa_sha512_raw": -8,
    "secp384r1_ecdsa_sha384_raw": -35,
    "secp521r1_ecdsa_sha512_raw": -36,
    "secp256k1_ecdsa_sha256_raw": -47,
}
COSE_MLDSA44 = -48

REQUIRED = [
    "aaguid", "description", "authenticatorVersion", "protocolFamily", "schema",
    "upv", "authenticationAlgorithms", "publicKeyAlgAndEncodings",
    "attestationTypes", "keyProtection", "matcherProtection", "tcDisplay",
    "attestationRootCertificates", "authenticatorGetInfo",
]
# Fields whose value tracks device state, not model identity.
STATEFUL = {"forcePINChange", "minPINLength"}
STATEFUL_OPTIONS = {"ep", "clientPin"}


def firmware_aaguid_bytes():
    src = open(CONSTS).read()
    m = re.search(r"pub const AAGUID:\s*\[u8;\s*16\]\s*=\s*\[(.*?)\];", src, re.S)
    if not m:
        sys.exit("could not find the AAGUID const in consts.rs")
    vals = [int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", m.group(1))]
    if len(vals) != 16:
        sys.exit(f"AAGUID const has {len(vals)} bytes, expected 16")
    return bytes(vals)


def part_a(stmt):
    fails = []

    for f in REQUIRED:
        if f not in stmt:
            fails.append(f"missing required field: {f}")

    gi = stmt.get("authenticatorGetInfo", {})

    # aaguid: dashed <-> dashless <-> firmware const
    dashed = stmt.get("aaguid", "")
    meta_bytes = bytes.fromhex(dashed.replace("-", ""))
    gi_bytes = bytes.fromhex(gi.get("aaguid", ""))
    fw_bytes = firmware_aaguid_bytes()
    if meta_bytes != fw_bytes:
        fails.append(f"aaguid {meta_bytes.hex()} != firmware const {fw_bytes.hex()}")
    if gi_bytes != fw_bytes:
        fails.append(f"authenticatorGetInfo.aaguid {gi_bytes.hex()} != const {fw_bytes.hex()}")

    # surrogate-only invariant
    if stmt.get("attestationTypes") == ["basic_surrogate"]:
        if stmt.get("attestationRootCertificates") != []:
            fails.append("basic_surrogate requires an empty attestationRootCertificates")

    # authenticationAlgorithms strings map exactly onto the classic COSE ids
    want = {ALG_STR_TO_COSE[s] for s in stmt.get("authenticationAlgorithms", [])
            if s in ALG_STR_TO_COSE}
    unknown = [s for s in stmt.get("authenticationAlgorithms", []) if s not in ALG_STR_TO_COSE]
    if unknown:
        fails.append(f"unknown authenticationAlgorithms strings: {unknown}")
    gi_cose = {a["alg"] for a in gi.get("algorithms", [])}
    if COSE_MLDSA44 in gi_cose:
        fails.append("default-profile statement should NOT advertise COSE -48 (ML-DSA)")
    if want != gi_cose:
        fails.append(f"alg mismatch: metadata {sorted(want)} vs getInfo {sorted(gi_cose)}")

    if stmt.get("authenticatorVersion") != gi.get("firmwareVersion"):
        fails.append("authenticatorVersion != authenticatorGetInfo.firmwareVersion")

    if fails:
        for f in fails:
            print(f"  FAIL: {f}")
        sys.exit(f"Part A: {len(fails)} failure(s)")
    print(f"Part A OK — aaguid {dashed}, algs {sorted(want)}, fw {gi.get('firmwareVersion')}")


def _norm(gi):
    """Drop stateful fields so the static surface can be compared."""
    out = {k: v for k, v in gi.items() if k not in STATEFUL}
    if "options" in out:
        out["options"] = {k: v for k, v in out["options"].items() if k not in STATEFUL_OPTIONS}
    return out


def part_b(stmt):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import importlib
        ten = importlib.import_module("10_fido_getinfo")
        import hid  # noqa: F401
    except Exception as e:
        print(f"Part B skipped (no hid / helper): {e}")
        return
    info = ten.find()
    if not info:
        print("Part B skipped — no FIDO HID device plugged in")
        return
    dev = ten.hid.device()
    dev.open_path(info["path"])
    try:
        ten.write(dev, b"\xff\xff\xff\xff" + bytes([ten.CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = ten.read(dev)[15:19]
        resp = ten.send_cbor(dev, cid, b"\x04")
        assert resp[0] == 0x00, f"getInfo status {resp[0]:#x}"
        m = ten.decode(resp[1:])
    finally:
        dev.close()

    live = {
        "versions": m[0x01],
        "extensions": m[0x02],
        "aaguid": m[0x03].hex(),
        "options": m[0x04],
        "maxMsgSize": m[0x05],
        "pinUvAuthProtocols": m[0x06],
        "maxCredentialCountInList": m[0x07],
        "maxCredentialIdLength": m[0x08],
        "algorithms": [{"alg": a["alg"], "type": a["type"]} for a in m[0x0A]],
        "maxSerializedLargeBlobArray": m[0x0B],
        "forcePINChange": m[0x0C],
        "minPINLength": m[0x0D],
        "firmwareVersion": m[0x0E],
        "maxCredBlobLength": m[0x0F],
    }
    if COSE_MLDSA44 in {a["alg"] for a in live["algorithms"]}:
        print("NOTE: live device is an advertise-pqc build (COSE -48 present); "
              "the statement targets the DEFAULT profile — comparison skipped.")
        return

    want = _norm(stmt["authenticatorGetInfo"])
    got = _norm(live)
    if want != got:
        for k in sorted(set(want) | set(got)):
            if want.get(k) != got.get(k):
                print(f"  DRIFT {k}: statement={want.get(k)} device={got.get(k)}")
        sys.exit("Part B: live getInfo drifted from the statement")
    print(f"Part B OK — live device getInfo matches the statement "
          f"(stateful fields {sorted(STATEFUL | STATEFUL_OPTIONS)} ignored)")


def main():
    stmt = json.load(open(META))
    part_a(stmt)
    part_b(stmt)


if __name__ == "__main__":
    main()
