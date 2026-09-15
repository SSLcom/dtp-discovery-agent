#!/usr/bin/env bash
#
# Assert that the maintainer scripts disable the timer on REMOVAL and never on
# UPGRADE.
#
# Debian's prerm and RPM's %preun both run on upgrade as well as removal, so a
# script that disables unconditionally stops an enrolled fleet reporting on a
# routine `apt upgrade` — silently, because nothing errors and the hosts simply
# go quiet. That is not something to establish by reading the packaging docs
# once; it is something to assert.
#
# `systemctl` is stubbed and its calls recorded, so this needs no booted systemd
# and runs anywhere.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/systemctl" <<'STUB'
#!/bin/sh
echo "$@" >> "$SYSTEMCTL_LOG"
exit 0
STUB
chmod +x "$work/systemctl"

fails=0

# run <label> <script> <arg> <expect: disable|no-disable>
run() {
  local label="$1" script="$2" arg="$3" expect="$4"
  export SYSTEMCTL_LOG="$work/calls"
  : > "$SYSTEMCTL_LOG"

  PATH="$work:$PATH" sh "$ROOT/packaging/scripts/$script" "$arg" >/dev/null 2>&1

  local got="no-disable"
  grep -q "disable" "$SYSTEMCTL_LOG" && got="disable"

  if [ "$got" = "$expect" ]; then
    printf '  PASS  %-46s %s\n' "$label" "$got"
  else
    printf '  FAIL  %-46s got %s, want %s\n' "$label" "$got" "$expect"
    fails=$((fails+1))
  fi
}

echo "preremove — the timer must survive every upgrade:"
run "debian: apt upgrade"            preremove.sh upgrade         no-disable
run "debian: deconfigure"            preremove.sh deconfigure     no-disable
run "debian: failed-upgrade"         preremove.sh failed-upgrade  no-disable
run "rpm: upgrade (1 left)"          preremove.sh 1               no-disable
run "rpm: downgrade (2 left)"        preremove.sh 2               no-disable
run "unrecognised argument"          preremove.sh wat             no-disable
run "no argument"                    preremove.sh ""              no-disable

echo
echo "preremove — and must stop on a genuine removal:"
run "debian: apt remove"             preremove.sh remove          disable
run "debian: apt purge"              preremove.sh purge           disable
run "rpm: erase (0 left)"            preremove.sh 0               disable

echo
echo "postinstall — installing is not enrolling:"
export SYSTEMCTL_LOG="$work/calls"; : > "$SYSTEMCTL_LOG"
PATH="$work:$PATH" sh "$ROOT/packaging/scripts/postinstall.sh" configure >/dev/null 2>&1
if grep -qE "enable|start" "$SYSTEMCTL_LOG"; then
  echo "  FAIL  postinstall enabled or started the timer"
  fails=$((fails+1))
else
  echo "  PASS  postinstall enables nothing (the agent has no account yet)"
fi

echo
echo "failures: $fails"
exit "$fails"
