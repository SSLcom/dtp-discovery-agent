#!/usr/bin/env bash
#
# Build every release artefact into dist/.
#
# THE RELEASE WORKFLOW CALLS THIS SCRIPT AND DOES NOTHING ELSE OF SUBSTANCE.
# Release logic buried in YAML can only be tested by cutting a release, which
# means the first time it is exercised for real is the first time anyone finds
# out it is wrong. Everything here runs identically on a laptop.
#
#   script/build-release.sh 1.2.3
#
# THE OUTPUT IS REPRODUCIBLE. Same source and same version in, byte-identical
# archives out — `-trimpath` keeps build paths out of the binary, and the
# archives are built with sorted entries, a fixed mtime and no owner metadata.
# So anyone can rebuild a published tag and check the checksums match, which is
# the only claim about provenance that does not rest on trusting us.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>" >&2; exit 2; }
VERSION="${VERSION#v}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# dist/ holds ONLY publishable artefacts, so `sha256sum -- *` over it needs no
# exclusions and cannot accidentally checksum a build directory. The unpacked
# per-platform trees live under build/, where the package step reads them.
DIST="$ROOT/dist"
STAGE="$ROOT/build/stage"
rm -rf "$DIST" "$ROOT/build"
mkdir -p "$DIST" "$STAGE"

# Fixed timestamp for every archive entry. Without it the mtime of the build
# machine's clock lands in the tarball and two builds of one commit differ.
: "${SOURCE_DATE_EPOCH:=0}"
export SOURCE_DATE_EPOCH

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

for target in $TARGETS; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  name="dtp-agent"
  [ "$goos" = "windows" ] && name="dtp-agent.exe"

  stage="$STAGE/${goos}_${goarch}"
  mkdir -p "$stage"

  echo "building $goos/$goarch"
  # CGO off: a binary that links the host's libc is not the single portable
  # artefact this is meant to be, and it would inherit a glibc version
  # requirement from whatever machine built it.
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o "$stage/$name" "$ROOT/cmd/dtp-agent"

  cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/"

  base="dtp-agent_${VERSION}_${goos}_${goarch}"
  if [ "$goos" = "windows" ]; then
    (cd "$stage" && python3 "$ROOT/script/zip.py" "$DIST/${base}.zip" .)
  else
    # --sort, a fixed --mtime and zeroed owners are what make this byte-stable.
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" \
        --owner=0 --group=0 --numeric-owner \
        -czf "$DIST/${base}.tar.gz" -C "$stage" .
  fi
done

# One checksum file over everything, so a downloader verifies with one fetch.
# See checksums.sh for why this is not a one-line redirect.
"$ROOT/script/checksums.sh" "$ROOT/dist"

echo
echo "dist/:"
(cd "$DIST" && ls -1)
