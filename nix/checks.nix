# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# `nix flake check` extras: keep the flake's own Nix formatted, and run the
# host-side cargo unit tests — the deterministic, sandbox-safe slice of
# scripts/check.sh — against the vendored deps. Run one alone with
# `nix build .#checks.<system>.<name>`.
{
  pkgs,
  toolchain,
  firmwareSrc,
  cargoDeps,
}:
let
  inherit (pkgs) lib;
  hostTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget;

  # The same host-testable crates scripts/check.sh runs (no_std libs whose unit
  # tests build for the host). The on-device tests/ scripts need real hardware
  # and stay out of the sandbox.
  hostCrates = [
    "rsk-sdk"
    "rsk-fs"
    "rsk-usb"
    "rsk-crypto"
    "rsk-fido"
    "rsk-openpgp"
    "rsk-rsa-asm"
    "rsk-mgmt"
    "rsk-oath"
    "rsk-otp"
    "rsk-piv"
    "rsk-rescue"
  ];
in
{
  # The check half of `nix fmt` — fails if any tracked .nix drifts from nixfmt.
  nixfmt = pkgs.runCommand "rsk-nixfmt-check" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
    nixfmt --check ${firmwareSrc}/flake.nix ${firmwareSrc}/nix/*.nix
    touch $out
  '';

  # Host cargo unit tests over the vendored deps — offline and pure. Matches
  # check.sh's profile (default `test`, not --release) so it stays quick.
  cargo-test = pkgs.stdenv.mkDerivation {
    name = "rsk-cargo-test";
    src = firmwareSrc;
    inherit cargoDeps;
    nativeBuildInputs = [
      pkgs.rustPlatform.cargoSetupHook
      toolchain
      pkgs.gcc-arm-embedded # rsk-rsa-asm's build.rs (cc) even on the host build
    ];
    buildPhase = ''
      runHook preBuild
      cargo test --offline --frozen --target ${hostTarget} \
        ${lib.concatMapStringsSep " " (c: "-p ${c}") hostCrates}
      runHook postBuild
    '';
    installPhase = "touch $out";
    doCheck = false;
  };
}
