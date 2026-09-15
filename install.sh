#!/bin/sh
#
# Install the DTP certificate discovery agent.
#
#   curl -fsSL https://raw.githubusercontent.com/SSLcom/dtp-discovery-agent/main/install.sh | sh
#
# THE CHECKSUM IS VERIFIED AND THE SCRIPT REFUSES TO PROCEED WITHOUT IT. This
# installs a binary that will run as root on your server; an installer that
# downloads over TLS and hopes is not good enough, because the whole point of
# the artefact chain is that you can check what you got. If SHA256SUMS cannot
# be fetched, or does not match, nothing is installed.
#
# If you would rather not pipe a script from the internet into a shell — a
# reasonable position, and this script is on GitHub precisely so you can read
# it first — the manual path is in the README: download the archive and the
# SHA256SUMS, verify, extract, move the binary onto your PATH.
set -eu

REPO="SSLcom/dtp-discovery-agent"
VERSION="${DTP_AGENT_VERSION:-latest}"
BIN_DIR="${DTP_AGENT_BIN_DIR:-/usr/local/bin}"

fail() { echo "install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

need curl
need tar
need install

# One of these, not either-or: macOS ships shasum, most Linux ships sha256sum.
if command -v sha256sum >/dev/null 2>&1; then
  verify_cmd="sha256sum -c --ignore-missing --status"
elif command -v shasum >/dev/null 2>&1; then
  verify_cmd="shasum -a 256 -c --ignore-missing --status"
else
  fail "neither sha256sum nor shasum found; refusing to install unverified"
fi

os="$(uname -s)"
case "$os" in
  Linux)  goos=linux ;;
  Darwin) goos=darwin ;;
  *) fail "unsupported operating system: $os (Windows: download the .zip from the releases page)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *) fail "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || fail "could not determine the latest release"
fi
VERSION="${VERSION#v}"

archive="dtp-agent_${VERSION}_${goos}_${goarch}.tar.gz"
base="https://github.com/${REPO}/releases/download/v${VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "installing dtp-agent ${VERSION} (${goos}/${goarch})"
curl -fsSL -o "$tmp/$archive" "$base/$archive" || fail "could not download $archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "could not download SHA256SUMS; refusing to install unverified"

# --ignore-missing so one checksum file covers every platform's artefacts while
# we verify only the one we fetched. grep first, so a SHA256SUMS that does not
# mention our archive at all is a failure rather than a vacuous pass: with
# nothing to check, `-c --ignore-missing` exits 0 and would wave it through.
grep -q "  ${archive}\$" "$tmp/SHA256SUMS" || fail "SHA256SUMS does not list ${archive}"
( cd "$tmp" && $verify_cmd SHA256SUMS ) || fail "checksum mismatch for ${archive} — NOT installing"

tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/dtp-agent" ] || fail "archive did not contain dtp-agent"

if [ -w "$BIN_DIR" ]; then
  install -m 0755 "$tmp/dtp-agent" "$BIN_DIR/dtp-agent"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "$tmp/dtp-agent" "$BIN_DIR/dtp-agent"
else
  fail "$BIN_DIR is not writable and sudo is unavailable; set DTP_AGENT_BIN_DIR"
fi

echo
echo "Installed $("$BIN_DIR/dtp-agent" version) to $BIN_DIR/dtp-agent"
cat <<'MSG'

It is not running yet. Enrol it, then let it report:

  dtp-agent enroll --server https://YOUR-DTP --account YOUR-ACCOUNT-ID --token dtpd_...
  dtp-agent run

To see what it WOULD report, without reporting anything:

  dtp-agent scan

MSG
