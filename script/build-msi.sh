#!/usr/bin/env bash
#
# Build the Windows installer into dist/.
#
# Run AFTER build-release.sh, which leaves the unpacked binaries in build/stage.
# Like the .deb and .rpm, this runs from a pinned container, so a laptop and a
# runner produce the same installer and the release path is exercised by anyone
# who wants to exercise it.
#
#   script/build-msi.sh 1.2.3
#
# THE MSI IS NOT BYTE-REPRODUCIBLE, AND THAT IS NOT AN OVERSIGHT. Measured: two
# builds of identical input differ, because an MSI carries a package-code UUID
# that wixl generates fresh each time and a created/last-saved timestamp taken
# from the clock. Neither is settable — `msibuild -s` can rewrite the package
# code but not the times — and SOURCE_DATE_EPOCH is ignored. So the MSI sits
# with the .deb and .rpm, OUTSIDE the reproducibility check the release workflow
# runs over the archives, and the repository's reproducibility claim continues
# to be about the archives exactly as the README words it.
#
# x64 ONLY. wixl refuses `-a arm64` outright ("arch of type 'arm64' is not
# supported"). Windows on ARM runs the x64 binary under emulation, and the arm64
# zip is published for anyone who would rather register the service by hand, so
# the gap costs a member on that platform one command rather than the product.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>" >&2; exit 2; }
VERSION="${VERSION#v}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="dtp-agent-wixl:0.101"

STAGE="build/stage/windows_amd64"
[ -x "$ROOT/$STAGE/dtp-agent.exe" ] || {
  echo "missing $STAGE/dtp-agent.exe — run build-release.sh first" >&2
  exit 1
}

# MSI has no concept of a prerelease: ProductVersion is up to three numeric
# fields and anything else is rejected. The release's dry run builds `0.0.0-dev`,
# so the suffix is dropped for the installer's internal version while the file
# name keeps the version that was asked for — otherwise the one path that
# exercises this script before a tag is pushed would be the one path that cannot
# run it.
MSI_VERSION="$(printf '%s' "$VERSION" | grep -oE '^[0-9]+(\.[0-9]+){0,2}' || true)"
[ -n "$MSI_VERSION" ] || { echo "version $VERSION has no numeric prefix to give the installer" >&2; exit 1; }

# The ProductCode identifies THIS version's package and must differ between
# versions or Windows treats an upgrade as a reinstall of what is already there.
# Derived from the UpgradeCode and the version rather than generated, so
# rebuilding a release produces a package Windows recognises as the same one —
# which is what lets a member repair or re-run an install without ending up with
# two entries in Add/Remove Programs.
UPGRADE_CODE="$(grep -oE 'UpgradeCode="[0-9A-Fa-f-]+"' "$ROOT/packaging/windows/dtp-agent.wxs" | head -1 | cut -d'"' -f2)"
[ -n "$UPGRADE_CODE" ] || { echo "could not read the UpgradeCode out of dtp-agent.wxs" >&2; exit 1; }
PRODUCT_CODE="$(python3 -c "
import sys, uuid
print(str(uuid.uuid5(uuid.UUID(sys.argv[1]), sys.argv[2])).upper())
" "$UPGRADE_CODE" "$VERSION")"

echo "building the installer for $VERSION (product $PRODUCT_CODE)"
docker build -q -t "$IMAGE" "$ROOT/packaging/windows" >/dev/null

OUT="dist/dtp-agent_${VERSION}_windows_amd64.msi"
docker run --rm -v "$ROOT":/work -w /work "$IMAGE" \
  wixl -a x64 -o "$OUT" \
    -D Version="$MSI_VERSION" \
    -D ProductCode="$PRODUCT_CODE" \
    -D BinarySource="$STAGE/dtp-agent.exe" \
    -D LicenseSource="LICENSE" \
    -D ReadmeSource="README.md" \
    packaging/windows/dtp-agent.wxs

# THE GUARD THAT MAKES THIS WORTH RUNNING. wixl reports success for a document
# whose elements it silently declined to act on, and an installer that lays down
# the binary and registers no service is the exact failure this whole change
# exists to fix — it would look installed, appear in Add/Remove Programs, and
# never report a certificate. So the built package is read back and asked
# whether the service is really in it.
"$ROOT/script/verify-msi.sh" "$ROOT/$OUT" "$IMAGE"

# One checksum file over everything, so a downloader verifies with one fetch.
"$ROOT/script/checksums.sh" "$ROOT/dist"

echo
echo "dist/:"
(cd "$ROOT/dist" && ls -1)
