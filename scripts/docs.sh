#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Build, preview, or link-check the documentation site (mdBook + Mermaid).
# Run inside the dev shell:
#   nix develop -c ./scripts/docs.sh serve    # live preview at localhost:3000
#   nix develop -c ./scripts/docs.sh build    # render the site into book/
#   nix develop -c ./scripts/docs.sh check    # build + offline broken-link check
set -euo pipefail
cd "$(dirname "$0")/.."

# mdbook-mermaid writes the (gitignored) mermaid.min.js / mermaid-init.js next to
# book.toml. Idempotent: it leaves book.toml untouched when the config is already
# present (it is, see book.toml), so this never dirties the tree.
ensure_mermaid() { mdbook-mermaid install . >/dev/null; }

cmd="${1:-build}"
case "$cmd" in
  serve)
    ensure_mermaid
    exec mdbook serve --open
    ;;
  build)
    ensure_mermaid
    mdbook build
    echo "Built site -> book/  (open book/index.html)"
    ;;
  check)
    ensure_mermaid
    mdbook build
    # Offline: resolves relative links against files on disk, skips web URLs.
    lychee --offline --no-progress README.md 'docs/**/*.md'
    echo "Docs build + link check OK"
    ;;
  *)
    echo "usage: $0 <serve|build|check>" >&2
    exit 2
    ;;
esac
