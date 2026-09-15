#!/usr/bin/env bash
#
# Put the .deb through install → upgrade → remove with REAL dpkg, and assert the
# three things that would each be silent in production:
#
#   1. an upgrade must not stop an enrolled fleet reporting
#   2. a removal must stop the timer
#   3. an enrolled host must keep its keypair — the identity DTP approved
#
# Real dpkg rather than a reading of the packaging docs: the whole bug this
# guards against was a wrong belief about which arguments dpkg passes to prerm.
# systemctl is stubbed, so no booted systemd is needed.
#
#   script/build-release.sh 0.0.1 && script/build-packages.sh 0.0.1 && \
#     script/test-package-lifecycle.sh 0.0.1
set -uo pipefail

VERSION="${1:-0.0.1}"
VERSION="${VERSION#v}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

deb="$(ls "$ROOT"/dist/*_amd64.deb 2>/dev/null | head -1)"
[ -n "$deb" ] || { echo "no amd64 .deb in dist/ — run build-packages.sh first" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$deb" "$work/old.deb"

# A second package, same bits, higher version — enough for dpkg to treat the
# install as an upgrade, which is all this is testing.
( cd "$ROOT" && ./script/build-packages.sh "${VERSION%.*}.99" >/dev/null 2>&1 )
newdeb="$(ls "$ROOT"/dist/*_amd64.deb 2>/dev/null | grep -v "$(basename "$deb")" | head -1)"
[ -n "$newdeb" ] || { echo "could not build the upgrade package" >&2; exit 2; }
cp "$newdeb" "$work/new.deb"

docker run --rm -v "$work":/d:ro debian:bookworm-slim bash -c '
set -e
mkdir -p /stub
cat > /stub/systemctl <<STUB
#!/bin/sh
echo "\$@" >> /tmp/systemctl.log
exit 0
STUB
chmod +x /stub/systemctl
export PATH=/stub:$PATH
fails=0

: > /tmp/systemctl.log
dpkg -i /d/old.deb >/dev/null 2>&1
[ "$(stat -c %a /var/lib/dtp-agent)" = 700 ] \
  && echo "  PASS  state directory is 0700" \
  || { echo "  FAIL  state directory is $(stat -c %a /var/lib/dtp-agent), want 700"; fails=$((fails+1)); }
dtp-agent version >/dev/null \
  && echo "  PASS  binary runs" \
  || { echo "  FAIL  binary does not run"; fails=$((fails+1)); }

# Enrolled: the keypair is what DTP has approved for this host.
printf -- "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n" > /var/lib/dtp-agent/agent.key
chmod 600 /var/lib/dtp-agent/agent.key

: > /tmp/systemctl.log
dpkg -i /d/new.deb >/dev/null 2>&1
grep -q disable /tmp/systemctl.log \
  && { echo "  FAIL  the upgrade disabled the timer — an enrolled fleet would go quiet"; fails=$((fails+1)); } \
  || echo "  PASS  the timer survived the upgrade"

: > /tmp/systemctl.log
dpkg -r dtp-agent >/dev/null 2>&1
grep -q disable /tmp/systemctl.log \
  && echo "  PASS  removal disabled the timer" \
  || { echo "  FAIL  removal left the timer enabled"; fails=$((fails+1)); }

[ -f /var/lib/dtp-agent/agent.key ] \
  && echo "  PASS  the approved keypair survived removal" \
  || { echo "  FAIL  removal destroyed the approved keypair"; fails=$((fails+1)); }

echo "failures: $fails"
exit $fails
'
