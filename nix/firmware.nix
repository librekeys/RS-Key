# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# `nix build` of the firmware image(s). Hand it pkgs + the cross target + the
# fenix toolchain (which carries the thumbv8m rust-std); it returns the package
# set and the `mkFirmware` builder. The output is an UNSIGNED firmware.uf2 —
# seal it with your secure-boot key separately (docs/production.md); the signing
# key never enters the build sandbox.
{
  pkgs,
  target,
  toolchain,
}:
let
  inherit (pkgs) lib;

  # Git deps (Cargo.lock) are vendored; these are their checkout hashes.
  # One per crate, but every embassy crate shares one git rev → one hash.
  embassyHash = "sha256-FhbDmObz+lZ3baMs0wDqm4an5XOPOYFqVBytCy4yeTc=";
  rpPacHash = "sha256-7WOfWaR5tofEveaM4NRFTFsX4GM2vja9YB0d+V1Mhng=";
  firmwareOutputHashes =
    (lib.genAttrs [
      "embassy-embedded-hal-0.6.0"
      "embassy-executor-0.10.0"
      "embassy-executor-macros-0.8.0"
      "embassy-executor-timer-queue-0.1.0"
      "embassy-futures-0.1.2"
      "embassy-hal-internal-0.5.0"
      "embassy-net-driver-0.2.0"
      "embassy-net-driver-channel-0.4.0"
      "embassy-rp-0.10.0"
      "embassy-sync-0.8.0"
      "embassy-time-0.5.1"
      "embassy-time-driver-0.2.2"
      "embassy-time-queue-utils-0.3.2"
      "embassy-usb-0.6.0"
      "embassy-usb-driver-0.2.2"
    ] (_: embassyHash))
    // {
      "rp-pac-7.0.0" = rpPacHash;
    };

  # Compile-time knobs (docs/build.md) are declarative Nix args on `mkFirmware`
  # — pure, no ambient env (see `firmware-pico` below and the exposed
  # `lib.${system}.mkFirmware`). As a convenience each arg also falls back to
  # the like-named env var, so `VIDPID=Pico nix build --impure .#firmware` works
  # too — but an explicit Nix arg always wins and needs no `--impure`.
  envOr =
    k: default:
    let
      v = builtins.getEnv k;
    in
    if v == "" then default else v;

  # Whole workspace minus build/VCS dirs (Cargo.lock + every crate source).
  firmwareSrc = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        b = baseNameOf path;
      in
      !(type == "directory" && (b == "target" || b == "result" || b == ".git"));
  };

  # Vendored crates.io + git deps, resolved once (shared with nix/checks.nix).
  cargoDeps = pkgs.rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    outputHashes = firmwareOutputHashes;
  };

  # name → a derivation producing <name>.elf + <name>.uf2.
  # Plain mkDerivation (not buildRustPackage): its build hook force-passes the
  # host `--target`, which mis-compiles cortex-m for the bare-metal target. We
  # drive cargo ourselves with `--target ${target}`, vendoring via
  # cargoSetupHook + importCargoLock. The repo .cargo/config.toml supplies the
  # link args (link.x / cortex-m33).
  mkFirmware =
    {
      name,
      cargoFlags ? [ ],
      vidpid ? envOr "VIDPID" null, # VIDPID preset (Yubikey5, Pico, Nitro3, …)
      usbVid ? envOr "USB_VID" null, # 0xHHHH raw VID override
      usbPid ? envOr "USB_PID" null, # 0xHHHH raw PID override
      fwVersion ? envOr "FW_VERSION" null, # X.Y.Z reported everywhere
      xoscDelayMult ? envOr "XOSC_DELAY_MULT" null, # 1..1024 crystal settle
      fakeMkek ? envOr "FAKE_MKEK" null, # 64 hex — TEST builds only
      fakeDevk ? envOr "FAKE_DEVK" null, # 64 hex — TEST builds only
    }:
    let
      # Non-null knobs become build-time env vars build.rs reads; each is part
      # of the derivation, so changing one rebuilds (just that crate).
      knobEnv = lib.filterAttrs (_: v: v != null) {
        VIDPID = vidpid;
        USB_VID = usbVid;
        USB_PID = usbPid;
        FW_VERSION = fwVersion;
        XOSC_DELAY_MULT = if xoscDelayMult == null then null else toString xoscDelayMult;
        FAKE_MKEK = fakeMkek;
        FAKE_DEVK = fakeDevk;
      };
    in
    pkgs.stdenv.mkDerivation (
      {
        pname = name;
        version = "5.7.4";
        src = firmwareSrc;
        inherit cargoDeps;
        nativeBuildInputs = [
          pkgs.rustPlatform.cargoSetupHook
          toolchain
          pkgs.gcc-arm-embedded # arm-none-eabi-gcc for rsk-rsa-asm's C+asm
          pkgs.picotool # ELF -> UF2
        ];
        buildPhase = ''
          runHook preBuild
          cargo build --release --offline --frozen \
            -p firmware --target ${target} \
            ${lib.escapeShellArgs cargoFlags}
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p "$out"
          elf="target/${target}/release/firmware"
          cp "$elf" "$out/${name}.elf"
          picotool uf2 convert "$elf" -t elf "$out/${name}.uf2"
          runHook postInstall
        '';
        doCheck = false;
        meta = {
          description = "RS-Key RP2350 firmware (${name}, unsigned UF2)";
          license = lib.licenses.agpl3Only;
        };
      }
      // knobEnv
    );
in
{
  # Reused by nix/checks.nix (host cargo tests share the src + vendored deps).
  inherit firmwareSrc cargoDeps;

  # `nix build` → default touch image; `.#firmware-no-touch` etc. mirror the CI
  # flavor matrix. All UNSIGNED — `picotool seal --sign` after.
  packages = {
    default = mkFirmware { name = "firmware"; };
    firmware = mkFirmware { name = "firmware"; };
    firmware-no-touch = mkFirmware {
      name = "firmware-no-touch";
      cargoFlags = [ "--no-default-features" ];
    };
    firmware-fips = mkFirmware {
      name = "firmware-fips";
      cargoFlags = [
        "--features"
        "fips-profile"
      ];
    };
    firmware-pqc = mkFirmware {
      name = "firmware-pqc";
      cargoFlags = [
        "--features"
        "advertise-pqc"
      ];
    };
    # Worked example of a declarative identity preset — copy this and tweak the
    # knobs for your own pinned config (vidpid / fwVersion / usbVid …).
    firmware-pico = mkFirmware {
      name = "firmware-pico";
      vidpid = "Pico";
    };
  };

  # The firmware builder itself, for arbitrary one-off declarative combos
  # without committing a package:
  #   nix build --impure --expr '(builtins.getFlake (toString ./.)).lib.${builtins.currentSystem}.mkFirmware { name = "fw"; vidpid = "Nitro3"; fwVersion = "2.0.0"; }'
  lib = { inherit mkFirmware; };
}
