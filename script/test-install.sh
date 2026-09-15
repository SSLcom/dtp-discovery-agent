#!/usr/bin/env bash
#
# Exercise install.sh against locally built artefacts, including the cases where
# it must REFUSE.
#
# install.sh puts a binary that runs as root onto a customer's server. Its
# refusals are the part worth testing: an installer that verifies a checksum on
# the happy path and waves anything else through has the security properties of
# one that does not verify at all.
#
#   script/build-release.sh 0.1.0 && script/test-install.sh 0.1.0
#
# NOTHING HERE ASSERTS THROUGH A PIPE. `if cmd | tail` takes the exit status of
# `tail`, which always succeeds — a first version of this file did exactly that
# and reported failures while the installer was behaving correctly.
set -uo pipefail

VERSION="${1:-0.1.0}"
VERSION="${VERSION#v}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

ARCHIVE="dtp-agent_${VERSION}_linux_amd64.tar.gz"
[ -f "$ROOT/dist/$ARCHIVE" ] || { echo "run build-release.sh $VERSION first" >&2; exit 2; }

work="$(mktemp -d)"
bindir="$work/bin"
serve="$work/serve/releases/download/v${VERSION}"
mkdir -p "$bindir" "$serve"
cp "$ROOT/dist/$ARCHIVE" "$ROOT/dist/SHA256SUMS" "$serve/"

( cd "$work/serve" && python3 -m http.server 8099 >/dev/null 2>&1 ) &
server=$!
trap 'kill "$server" 2>/dev/null; rm -rf "$work"' EXIT INT TERM
sleep 2

sed -e 's|https://github.com/${REPO}/releases/download|http://127.0.0.1:8099/releases/download|' \
    "$ROOT/install.sh" > "$work/install-local.sh"

fails=0
code=0

attempt() {
  rm -f "$bindir/dtp-agent"
  DTP_AGENT_VERSION="$VERSION" DTP_AGENT_BIN_DIR="$bindir" \
    sh "$work/install-local.sh" > "$work/out" 2>&1
  code=$?
  sed 's/^/    /' < "$work/out" | tail -2
  echo "    exit=$code"
}

check() { # check <description> <expect-installed yes|no> <expect-zero-exit yes|no>
  local want_installed="$2" want_zero="$3" installed="no" ok=1
  [ -f "$bindir/dtp-agent" ] && installed="yes"
  [ "$installed" = "$want_installed" ] || ok=0
  if [ "$want_zero" = yes ]; then [ "$code" -eq 0 ] || ok=0; else [ "$code" -ne 0 ] || ok=0; fi
  if [ "$ok" = 1 ]; then echo "    PASS"; else echo "    FAIL: $1"; fails=$((fails+1)); fi
}

echo "=== honest artefacts — installs"
attempt; check "should install" yes yes

echo
echo "=== tampered archive, honest SHA256SUMS — refuses"
printf 'malicious' >> "$serve/$ARCHIVE"
attempt; check "must refuse a tampered archive" no no

echo
echo "=== SHA256SUMS does not list the archive — refuses"
cp "$ROOT/dist/$ARCHIVE" "$serve/"
grep -v linux_amd64 "$ROOT/dist/SHA256SUMS" > "$serve/SHA256SUMS"
attempt; check "must refuse an archive the sums file does not cover" no no

echo
echo "=== SHA256SUMS unavailable — refuses rather than installing unverified"
rm -f "$serve/SHA256SUMS"
attempt; check "must refuse when it cannot verify" no no

echo
echo "failures: $fails"
exit "$fails"
