# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

{
  description = "RS-Key (RSK) — an open security-key firmware for the RP2350: FIDO2, OpenPGP, PIV, OATH, OTP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  # The per-system pieces live in nix/: firmware.nix (the `nix build` packages +
  # the mkFirmware builder), host-tools.nix (the Python + rsk/rsk-tui commands),
  # devshells.nix (the dev + fuzz shells), and checks.nix (`nix flake check`).
  # This file just wires the shared context (pkgs, the cross target, the
  # toolchains) into them.
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        fx = fenix.packages.${system};

        # RP2350 = dual Cortex-M33 -> thumbv8m.main-none-eabihf (hardware float).
        # (RP2350 also has RISC-V Hazard3 cores; we target the ARM cores, which embassy-rp supports.)
        target = "thumbv8m.main-none-eabihf";

        toolchain = fx.combine [
          fx.stable.toolchain
          fx.targets.${target}.stable.rust-std
        ];

        # cargo-fuzz needs nightly (libfuzzer + -Zsanitizer); host target only.
        fuzzToolchain = fx.complete.toolchain;

        hostTools = import ./nix/host-tools.nix { inherit pkgs; };
        firmware = import ./nix/firmware.nix { inherit pkgs target toolchain; };
      in
      {
        inherit (firmware) packages lib;

        devShells = import ./nix/devshells.nix (
          {
            inherit
              pkgs
              target
              toolchain
              fuzzToolchain
              ;
          }
          // hostTools
        );

        # `nix fmt` formats the flake's Nix; `nix flake check` runs nix/checks.nix.
        # Plain nixfmt only takes file args, so wrap it to recurse the tree when
        # `nix fmt` is called with none.
        formatter = pkgs.writeShellApplication {
          name = "fmt";
          runtimeInputs = [ pkgs.nixfmt ];
          text = ''
            targets=("$@")
            if [ "''${#targets[@]}" -eq 0 ]; then targets=("."); fi
            find "''${targets[@]}" -name '*.nix' -not -path '*/.git/*' -print0 \
              | xargs -0 -r nixfmt
          '';
        };

        checks = import ./nix/checks.nix {
          inherit pkgs toolchain;
          inherit (firmware) firmwareSrc cargoDeps;
        };
      }
    );
}
