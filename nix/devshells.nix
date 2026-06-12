# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# The dev shells: `default` (toolchain + picotool + security tooling + the host
# `rsk`/`rsk-tui` commands) and `fuzz` (nightly for cargo-fuzz).
{
  pkgs,
  target,
  toolchain,
  fuzzToolchain,
  rskPython,
  rskBin,
  rskTui,
}:
{
  default = pkgs.mkShell {
    packages = [
      toolchain
      pkgs.flip-link # stack-overflow-safe linker for embedded
      pkgs.probe-rs-tools # flash/debug over SWD (optional; needs a probe)
      pkgs.picotool # ELF -> UF2 + BOOTSEL flashing, no probe needed
      pkgs.pkg-config
      pkgs.gcc-arm-embedded
      # arm-none-eabi-gcc — builds rsk-rsa-asm's C+ARM-asm
      # fast RSA modexp. `cc` auto-detects it.

      pkgs.yubikey-manager # ykman CLI (device management, guides)
      pkgs.libgcrypt # the vendored OpenPGP card suite loads it via ctypes

      # Security tooling (see scripts/check.sh).
      pkgs.gitleaks # secret detection (pre-commit hook over staged diff)
      pkgs.cargo-audit # SCA: RustSec advisory scan of Cargo.lock
      pkgs.cargo-deny # SCA: advisories + licenses + source/ban policy

      # Host-side tooling: the `rsk` CLI (tools/rsk) + the `rsk-tui` dashboard
      # (tools/tui) + the CTAPHID/FIDO device tests (tests/). See host-tools.nix
      # for the Python deps.
      rskPython
      rskBin
      rskTui
    ];

    shellHook = ''
      # the Gnuk-derived OpenPGP card suite (third_party/) dlopens libgcrypt
      export DYLD_FALLBACK_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
      export LD_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

      # Install repo git hooks (idempotent; symlinked so edits take effect).
      if [ -d .git ] && [ -f scripts/hooks/pre-commit ]; then
        ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
      fi

      echo "rs-key devshell"
      echo "  rustc:    $(rustc --version 2>/dev/null)"
      echo "  target:   ${target}"
      echo "  picotool: $(picotool version 2>/dev/null | head -1 || echo 'n/a')"
      echo
      echo "Build:  cargo build --release -p firmware   # pick the target crate"
      echo "  (or:  nix build .#firmware                 # hermetic → result/firmware.uf2)"
      echo "UF2:    picotool uf2 convert target/${target}/release/firmware -t elf firmware.uf2"
      echo "Flash:  hold BOOTSEL, plug in the RP2350, drag firmware.uf2 to the RP2350 drive"
      echo "Check:  ./scripts/check.sh        # fmt + clippy + test + audit + deny + gitleaks"
      echo "Fuzz:   nix develop .#fuzz -c cargo fuzz run <target>"
      echo "CLI:    rsk status | rsk backup … | rsk secure-boot … | rsk otp … (rsk --help)"
      echo "TUI:    rsk-tui                    # live device dashboard"
    '';
  };

  # Nightly shell for cargo-fuzz: `nix develop .#fuzz -c cargo fuzz run apdu`.
  fuzz = pkgs.mkShell {
    packages = [
      fuzzToolchain
      pkgs.cargo-fuzz
    ];
    shellHook = ''
      echo "rs-key fuzz devshell (nightly)"
      echo "  rustc: $(rustc --version 2>/dev/null)"
      echo "List:   cargo fuzz list"
      echo "Run:    cargo fuzz run <target> -- -max_total_time=30"
    '';
  };
}
