# Releases & verification

Releases live on the [GitHub Releases](https://github.com/TheMaxMur/RS-Key/releases)
page. Each is cut from a `v*` git tag by the
[release workflow](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/release.yml),
which builds every artifact reproducibly, hashes it, and signs the manifest.

## What a release contains

- **Eight firmware images** — `rs-key-<tag>-<flavor>.uf2`, the cross product of
  the build flags (`up-button` × `advertise-pqc` × `fips-profile`):

  | flavor | flags | use |
  |---|---|---|
  | `default` | touch | the normal build — start here |
  | `pqc` | + advertise-pqc | advertises ML-DSA-44 in getInfo (breaks old Firefox) |
  | `fips` | + fips-profile | the locked FIPS-style policy ([guides/fips.md](guides/fips.md)) |
  | `fips-pqc` | + both | |
  | `no-touch` | presence off | **test builds** — the automated suites can't press a button |
  | `no-touch-pqc` / `no-touch-fips` / `no-touch-fips-pqc` | … | test variants |

  All eight present the default **RS-Key** USB identity (`0x1209:0x0001`). For the
  YubiKey-interop identity, build `VIDPID=Yubikey5` yourself ([build.md](build.md)).
- **`SHA256SUMS`** — a checksum for every image and the SBOM.
- **`SHA256SUMS.cosign.bundle`** — a keyless [cosign](https://docs.sigstore.dev/)
  signature of `SHA256SUMS` (sigstore/Fulcio; the signer is the reusable build
  workflow's GitHub OIDC identity — `release-build.yml`, see the verify step
  below — logged in Rekor).
- **`rs-key-<tag>-sbom.cdx.json`** — a CycloneDX software bill of materials for the
  firmware's dependency tree.

> **The images are UNSIGNED for secure boot.** The cosign signature attests *who
> built them*, not the boot seal. On a secure-boot device you seal an image with
> your own key before flashing — `nix run .#flash` does it, or see
> [production.md](production.md). The reproducibility claim is about the unsigned
> payload (a seal is signer-specific and not reproducible by a third party).

## Verify a download

Grab the images you want plus `SHA256SUMS` and `SHA256SUMS.cosign.bundle`.

```sh
# 1. the checksums file is authentic (keyless cosign — needs cosign >= 2.0)
#    The signer is the *reusable* build workflow (release-build.yml), not the
#    thin release.yml caller: a workflow_call job's OIDC identity is its own
#    job_workflow_ref, so that is what the Fulcio cert's SAN carries.
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/TheMaxMur/RS-Key/\.github/workflows/release-build\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

# 2. the images match the (now-trusted) checksums
sha256sum -c SHA256SUMS
```

Both must pass. Step 1 proves `SHA256SUMS` was produced by this repo's release
workflow; step 2 ties each `.uf2` (and the SBOM) to it.

## Verify the build is reproducible

The images are bit-for-bit reproducible per platform, per `flake.lock`, so you can
rebuild them yourself and compare — no need to trust the published binary:

```sh
git checkout <tag>
nix build .#firmware              # the default flavor (others: .#firmware-fips, …)
sha256sum result/firmware.uf2     # compare against SHA256SUMS for rs-key-<tag>-default.uf2
```

A match on Linux reproduces the CI-built artifact exactly. (Cross-platform
identity — macOS vs Linux — is not guaranteed; the canonical bytes are the
Linux ones the workflow publishes.)
