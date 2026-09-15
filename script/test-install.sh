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

# A FREE PORT, chosen now rather than assumed. A previous run's orphaned server
# holding the port does not make this one fail loudly — it makes it serve a
# directory that no longer exists, and then every "refuses" case passes because
# the download 404s rather than because verification worked. That is a suite
# reporting success while testing nothing.
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
base="http://127.0.0.1:${port}"

( cd "$work/serve" && python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 ) &
server=$!
trap 'kill "$server" 2>/dev/null; rm -rf "$work"' EXIT INT TERM

# Wait for it, and PROVE it serves the artefact before asserting anything.
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "$base/releases/download/v${VERSION}/$ARCHIVE" 2>/dev/null && break
  sleep 0.2
done
if ! curl -fsS -o /dev/null "$base/releases/download/v${VERSION}/$ARCHIVE" 2>/dev/null; then
  echo "fixture is not serving $ARCHIVE — refusing to report results" >&2
  exit 2
fi

sed -e "s|https://github.com/\${REPO}/releases/download|${base}/releases/download|" \
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

# check <description> <expect-installed yes|no> <expect-zero-exit yes|no> [reason-pattern]
#
# A refusal must be for the REASON under test. Without the pattern, a broken
# fixture — a 404, a dead server — refuses too, and the case passes while
# proving nothing about verification.
check() {
  local want_installed="$2" want_zero="$3" reason="${4:-}" installed="no" ok=1 why=""
  [ -f "$bindir/dtp-agent" ] && installed="yes"
  [ "$installed" = "$want_installed" ] || { ok=0; why="installed=$installed"; }
  if [ "$want_zero" = yes ]; then
    [ "$code" -eq 0 ] || { ok=0; why="$why exit=$code"; }
  else
    [ "$code" -ne 0 ] || { ok=0; why="$why exit=0"; }
  fi
  if [ -n "$reason" ] && ! grep -qi -- "$reason" "$work/out"; then
    ok=0; why="$why (refused, but not for: $reason)"
  fi
  if [ "$ok" = 1 ]; then echo "    PASS"; else echo "    FAIL: $1 — $why"; fails=$((fails+1)); fi
}

echo "=== honest artefacts — installs"
attempt; check "should install" yes yes

echo
echo "=== tampered archive, honest SHA256SUMS — refuses"
printf 'malicious' >> "$serve/$ARCHIVE"
attempt; check "must refuse a tampered archive" no no "checksum mismatch"

echo
echo "=== SHA256SUMS does not list the archive — refuses"
cp "$ROOT/dist/$ARCHIVE" "$serve/"
grep -v linux_amd64 "$ROOT/dist/SHA256SUMS" > "$serve/SHA256SUMS"
attempt; check "must refuse an archive the sums file does not cover" no no "does not list"

echo
echo "=== SHA256SUMS unavailable — refuses rather than installing unverified"
rm -f "$serve/SHA256SUMS"
attempt; check "must refuse when it cannot verify" no no "refusing to install unverified"

echo
echo "failures: $fails"
exit "$fails"
