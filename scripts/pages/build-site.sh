#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Build the *versioned* documentation site into <out> (default: site/):
#   main     -> <out>/            (root — the default version Pages serves)
#   develop  -> <out>/develop/
#   v*       -> <out>/<tag>/      (one dir per release tag)
#
# Each version is built from its own git ref in a throwaway worktree, with a
# per-version mdBook site-url so absolute links and the 404 page resolve under
# the right subpath. A versions.json manifest is written at the site root.
#
# Needs git + mdbook + mdbook-mermaid on PATH. CI runs it inside the nix shell;
# the repo must have every ref available (actions/checkout fetch-depth: 0).
# Locally:  nix develop -c ./scripts/pages/build-site.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

OUT_ARG="${1:-site}"
BASE="${PAGES_BASE:-/RS-Key/}"          # Pages base path; CI passes it from configure-pages
case "$BASE" in */) ;; *) BASE="$BASE/" ;; esac

rm -rf "$OUT_ARG"
mkdir -p "$OUT_ARG"
OUT="$(cd "$OUT_ARG" && pwd)"           # absolute: mdbook output is copied here

WT_ROOT="$(mktemp -d)"
trap 'rm -rf "$WT_ROOT"' EXIT

manifest=()                             # "name|path" entries for versions.json

SWITCHER="scripts/pages/version-switcher.js"   # GUI version selector, copied to root

# Inject the version-switcher <script> into every built HTML page (idempotent),
# so even tags whose sources predate the switcher get it. perl keeps the in-place
# edit portable across the GNU/BSD sed split.
inject_switcher() {
  local dir="$1"
  local tag="<script defer src=\"${BASE}version-switcher.js\" data-rsk-base=\"${BASE}\"></script>"
  find "$dir" -name '*.html' -type f -print0 | while IFS= read -r -d '' f; do
    grep -q 'version-switcher.js' "$f" || perl -0pi -e "s#</head>#$tag\n</head>#" "$f"
  done
}

# Resolve a branch to a buildable ref, preferring the remote-tracking copy
# (CI checks out one branch; the others live under origin/*).
resolve() {
  local b="$1"
  if   git rev-parse --verify -q "origin/$b^{commit}" >/dev/null; then echo "origin/$b"
  elif git rev-parse --verify -q "$b^{commit}"        >/dev/null; then echo "$b"
  fi
}

# build_version <ref> <name> <subdir>   (subdir "" = site root)
build_version() {
  local ref="$1" name="$2" sub="$3"
  if [ -z "$ref" ]; then echo "skip: '$name' — ref not found"; return 0; fi
  local wt="$WT_ROOT/${sub:-root}"
  git worktree add --force --detach "$wt" "$ref" >/dev/null
  if [ -f "$wt/book.toml" ]; then
    local url="$BASE${sub:+$sub/}" dest="$OUT${sub:+/$sub}"
    echo "build: $name ($ref) -> ${sub:-<root>}  site-url=$url"
    (
      cd "$wt"
      mdbook-mermaid install . >/dev/null
      MDBOOK_OUTPUT__HTML__SITE_URL="$url" mdbook build >/dev/null
    )
    mkdir -p "$dest"
    cp -R "$wt/book/." "$dest/"
    inject_switcher "$dest"
    manifest+=("$name|${sub:+$sub/}")
  else
    echo "skip: '$name' ($ref) has no book.toml (predates the docs site)"
  fi
  git worktree remove --force "$wt"
}

build_version "$(resolve main)"    "main"    ""
build_version "$(resolve develop)" "develop" "develop"

# Publish the newest PAGES_TAG_LIMIT tags (default 10; 0/empty/non-numeric =
# every tag). Capped to bound CI wall-clock: rebuild-all rebuilds every version
# on every run. Tags older than the cap stop being published (their /vX/ 404s).
TAG_LIMIT="${PAGES_TAG_LIMIT:-10}"
all_tags="$(git tag --list 'v*' --sort=-v:refname)"
n_all="$(printf '%s\n' "$all_tags" | grep -c . || true)"
if [[ "$TAG_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
  tags="$(printf '%s\n' "$all_tags" | head -n "$TAG_LIMIT")"
  if [ "$n_all" -gt "$TAG_LIMIT" ]; then
    echo "note: publishing newest $TAG_LIMIT of $n_all tags (older versions dropped)"
  fi
else
  tags="$all_tags"
fi
while IFS= read -r tag; do
  [ -n "$tag" ] && build_version "$tag" "$tag" "$tag"
done <<EOF
$tags
EOF

if [ "${#manifest[@]}" -eq 0 ]; then
  echo "error: nothing built (no buildable refs found)" >&2
  exit 1
fi

cp "$SWITCHER" "$OUT/version-switcher.js"

# versions.json — machine-readable index of what got published (main first,
# then develop, then tags newest-first; consumed by humans / future tooling).
{
  printf '{\n  "base": "%s",\n  "versions": [\n' "$BASE"
  last=$(( ${#manifest[@]} - 1 ))
  for i in "${!manifest[@]}"; do
    name="${manifest[$i]%|*}"; path="${manifest[$i]#*|}"
    sep=","; [ "$i" -eq "$last" ] && sep=""
    printf '    { "name": "%s", "path": "%s" }%s\n' "$name" "$path" "$sep"
  done
  printf '  ]\n}\n'
} >"$OUT/versions.json"

echo "done -> $OUT  (${#manifest[@]} versions)"
