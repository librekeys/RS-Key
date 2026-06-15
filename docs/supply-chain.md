<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Supply chain

How a downloaded RS-Key release proves it came from this source tree, was built
by this project's CI, and pulls in only reviewed dependencies — and how you
verify each of those claims yourself.

**No private keys are involved here.** The build provenance is keyless
(sigstore/Fulcio, signed against this workflow's GitHub OIDC identity, recorded
in the public Rekor transparency log). The only signing key in the project is
the *secure-boot* key, which is a different thing entirely — it seals an image
so the RP2350 bootrom will run it; it has nothing to do with the supply chain.
See [production.md](production.md) for that.

## What every release carries

| Layer | Artifact | What it proves |
|---|---|---|
| Reproducible build | the 8 `.uf2` flavors | the binary is a pure function of the source at the tag — anyone can rebuild it |
| Repro **gate** | (CI, blocking) | the release job *fails* if any flavor doesn't rebuild bit-identical, so a non-reproducible image is never published |
| Checksums + signature | `SHA256SUMS` + `SHA256SUMS.cosign.bundle` | the hashes were signed by this repo's release workflow (keyless cosign) |
| Build provenance | a GitHub **attestation** (not a release file) | which reusable workflow, at which commit, on which runner built each `.uf2` — **SLSA v1 Build L3**, keyless via `attest-build-provenance` |
| SBOM | `rs-key-<tag>-sbom.cdx.json` | the CycloneDX bill of materials for the firmware crate |
| Dependency audit | `supply-chain/` (in-repo) | every dependency is covered by an imported audit or a recorded exemption (cargo-vet) |

## Verifying a download

### 1. Reproducible build

Rebuild from the tagged source and compare — the strongest check, because it
needs no trust in the publisher at all:

```sh
git checkout <tag>
nix build .#firmware            # or .#firmware-pqc, .#firmware-fips, …
sha256sum result/firmware.uf2   # compare against SHA256SUMS
```

CI already enforces this: the release job rebuilds all eight flavors with
`nix build --rebuild` and fails on any bit-level difference before publishing.

### 2. Checksum signature (keyless cosign)

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/TheMaxMur/RS-Key/\.github/workflows/release-build\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS          # then check the artifacts against it
```

The certificate identity is **`release-build.yml`**, not `release.yml`: cosign
runs inside the reusable builder, and Sigstore stamps the cert with the reusable
workflow's identity (`job_workflow_ref`).

### 3. Build provenance (GitHub attestation)

```sh
gh attestation verify rs-key-<tag>-default.uf2 \
  --repo TheMaxMur/RS-Key \
  --signer-workflow TheMaxMur/RS-Key/.github/workflows/release-build.yml
```

This confirms the `.uf2` was built by the **`release-build.yml` reusable
workflow** in this repo — the attestation records the workflow, commit and
runner, so a hand-built upload won't verify. Pinning `--signer-workflow` to the
reusable builder is the **SLSA Build L3** check: it proves a *specific, trusted*
workflow produced the artifact, not merely that something in the repo did.
(Dropping `--signer-workflow` still verifies an attestation exists for this repo —
a weaker, Build-L2-style check.) The provenance is a GitHub attestation
(Sigstore-signed, logged in Rekor) kept in the attestation API rather than as a
release asset, so it stays available even though the published release is
immutable.

## Dependency review — cargo-vet

`cargo-deny` already blocks bad licenses and known advisories. `cargo-vet`
answers a different question — *has anyone actually reviewed this crate's code?*
— by requiring every dependency to be covered by a recorded audit.

The audit set lives in [`supply-chain/`](https://github.com/TheMaxMur/RS-Key/tree/main/supply-chain):
imported audits from Mozilla, Google, ISRG and Zcash, plus our own
`exemptions` for everything they don't cover. The gate runs in `check.sh`:

```sh
nix develop -c cargo vet --locked
```

**Honest scope.** RS-Key is an embedded tree — embassy, the RP2350 HAL, `defmt`
and many RustCrypto crates are not in the big organizations' audit sets, so they
are recorded as **exemptions** (grandfathered in, not yet line-reviewed). The
value is not "every line audited"; it is that a **new, unreviewed crate cannot
enter the tree silently** — it fails `cargo vet` until it's audited, imported, or
explicitly exempted. To see the current state and shrink the exemption list:

```sh
nix develop -c cargo vet              # what's audited vs exempted
nix develop -c cargo vet suggest      # diffs to review next
```

The host `tools/tui` workspace is separate and not yet under cargo-vet; it is
covered by Dependabot and `cargo-deny`.

## What's deliberately *not* here

- **No `cargo-vet` of a fully line-reviewed tree.** See the honest scope above.
- **No image encryption / signed-for-boot release artifacts.** The published
  `.uf2`s are unsigned for secure boot by design — you seal them with your own
  key ([production.md](production.md)). The signatures on this page attest the
  build, not the boot.

See also: [releases.md](releases.md) for the release index, and
[COMPLIANCE.md](https://github.com/TheMaxMur/RS-Key/blob/main/COMPLIANCE.md) for
the licensing posture.
