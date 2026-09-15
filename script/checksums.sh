#!/usr/bin/env bash
#
# Write dist/SHA256SUMS over every artefact — and NOT over itself.
#
# `sha256sum -- * > SHA256SUMS` is the obvious spelling and it is wrong: the
# shell creates the output file before the glob is expanded, so the sums file
# lists itself with the hash of its own empty first moment. That entry can never
# match, and `sha256sum -c` then FAILS THE WHOLE FILE — which took the installer
# down with it while every individual artefact was perfectly fine.
#
# Written outside dist/ and moved in, so there is no window in which the glob
# could see it.
set -euo pipefail

DIST="${1:?usage: checksums.sh <dist-dir>}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

rm -f "$DIST/SHA256SUMS"
( cd "$DIST" && sha256sum -- * ) > "$tmp"

# The guard for the bug above: if the sums file ever lists itself again, say so
# here rather than letting every downloader discover it.
if grep -q '  SHA256SUMS$' "$tmp"; then
  echo "checksums: SHA256SUMS lists itself; verification would always fail" >&2
  exit 1
fi

mv "$tmp" "$DIST/SHA256SUMS"
trap - EXIT
