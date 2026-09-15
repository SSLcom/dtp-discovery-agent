#!/usr/bin/env bash
#
# Build the .deb and .rpm for each Linux architecture, into dist/.
#
# Run AFTER build-release.sh, which leaves the unpacked binaries in build/stage.
# Uses nfpm from its container image when nfpm is not on PATH, so this produces
# the same packages on a laptop as it does on a runner — a release step that can
# only be exercised by cutting a release is one nobody has tested.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>" >&2; exit 2; }
VERSION="${VERSION#v}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# PINNED BY DIGEST, not by tag. A tag can be moved to different bytes; a digest
# cannot. This image builds the packages a customer installs as root, so what
# "v2.38.0" means must not be something a third party can change under us.
NFPM_IMAGE="goreleaser/nfpm@sha256:650f332ea4ce721d735c8e74ce6d66127d61fe01d25b1296ff965ce282afa122"

run_nfpm() {
  # The container is the DEFAULT, not the fallback: pinning the image is what
  # makes local and CI packaging the same bytes. A locally installed nfpm is
  # used only when asked for explicitly (NFPM_LOCAL=1), for someone iterating.
  if [ "${NFPM_LOCAL:-0}" = "1" ] && command -v nfpm >/dev/null 2>&1; then
    (cd "$ROOT" && VERSION="$VERSION" ARCH="$ARCH" nfpm package --config packaging/nfpm.yaml --packager "$1" --target dist/)
  else
    docker run --rm \
      -v "$ROOT":/work -w /work \
      -e VERSION="$VERSION" -e ARCH="$ARCH" \
      "$NFPM_IMAGE" package --config packaging/nfpm.yaml --packager "$1" --target dist/
  fi
}

for ARCH in amd64 arm64; do
  export ARCH
  [ -x "$ROOT/build/stage/linux_${ARCH}/dtp-agent" ] || {
    echo "missing build/stage/linux_${ARCH}/dtp-agent — run build-release.sh first" >&2
    exit 1
  }
  echo "packaging linux/${ARCH}"
  # nfpm reads contents.src literally, so the architecture is selected by what
  # is at this path rather than by a variable inside the config.
  rm -rf "$ROOT/build/pkg"
  mkdir -p "$ROOT/build/pkg"
  cp "$ROOT/build/stage/linux_${ARCH}/dtp-agent" "$ROOT/build/pkg/dtp-agent"

  run_nfpm deb
  run_nfpm rpm
done

# One checksum file over everything, so a downloader verifies with one fetch.
# See checksums.sh for why this is not a one-line redirect.
"$ROOT/script/checksums.sh" "$ROOT/dist"

echo
echo "dist/:"
(cd "$ROOT/dist" && ls -1)
