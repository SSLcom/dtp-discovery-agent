#!/usr/bin/env bash
#
# Read a built .msi back and check it installs what it claims to.
#
# WHY THIS EXISTS. wixl exits 0 for a document containing elements it silently
# declined to act on — measured: an <Environment> element is a hard error, but
# an unsupported ATTRIBUTE is a warning on stderr and the build succeeds
# without it. So "the installer built" says nothing about whether the service
# is in it, and an installer that lays down the binary and registers no service
# is precisely the failure this packaging exists to prevent: it installs
# cleanly, appears in Add/Remove Programs, and never reports a certificate.
#
# Nothing here can run the installer — that needs Windows. What it CAN do is
# read the tables Windows would act on, which catches everything between "the
# XML was accepted" and "the service is registered".
#
#   script/verify-msi.sh dist/dtp-agent_1.2.3_windows_amd64.msi [image]
set -euo pipefail

MSI="${1:-}"
[ -n "$MSI" ] || { echo "usage: $0 <msi> [image]" >&2; exit 2; }
IMAGE="${2:-dtp-agent-wixl:0.101}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WXS="$ROOT/packaging/windows/dtp-agent.wxs"

# Read the expected values out of the WiX source rather than repeating them
# here. A copy in this script would be a third place for the service's name to
# live, and the one most likely to be forgotten.
# `|| true` on both, and it is load-bearing: `set -o pipefail` turns a grep
# that matches nothing into a failed assignment, and `set -e` then exits here
# with no output at all. The check below is the one that should speak.
SERVICE_NAME="$(grep -A3 '<ServiceInstall' "$WXS" | grep -oE 'Name="[^"]+"' | head -1 | cut -d'"' -f2 || true)"
SERVICE_ARGS="$(grep -oE 'Arguments="[^"]+"' "$WXS" | head -1 | cut -d'"' -f2 || true)"
[ -n "$SERVICE_NAME" ] && [ -n "$SERVICE_ARGS" ] || {
  echo "verify-msi: dtp-agent.wxs declares no service to check for" >&2
  exit 1
}

dir="$(cd "$(dirname "$MSI")" && pwd)"
base="$(basename "$MSI")"

# msiinfo export writes THREE header lines — column names, column types, table
# name — and CRLF endings, before any data. `rows` drops the header and the
# carriage returns, which matters more than it looks: wixl creates the
# ServiceInstall TABLE even when nothing declared a service, so a dump that is
# merely non-empty proves nothing at all. Only a data row does.
dump() {
  docker run --rm -v "$dir":/m -w /m "$IMAGE" msiinfo export "$base" "$1" 2>/dev/null | tr -d '\r' || true
}
rows() { dump "$1" | tail -n +4; }

fail=0
check() {
  local what="$1" haystack="$2" needle="$3"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    echo "  ok    $what"
  else
    echo "  FAIL  $what (expected $needle)" >&2
    fail=1
  fi
}

echo "verifying $base"

check "the agent binary is in the package" "$(rows File)" "dtp-agent.exe"

install="$(rows ServiceInstall)"
[ -n "$install" ] || {
  echo "  FAIL  the package registers no service at all — it would install the binary and never run it" >&2
  exit 1
}
check "the service is named $SERVICE_NAME"        "$install" "$SERVICE_NAME"
check "it starts the binary with '$SERVICE_ARGS'" "$install" "$SERVICE_ARGS"
check "it runs as LocalSystem"                    "$install" "LocalSystem"

# ServiceInstall's numeric columns, which is where a silently dropped attribute
# would show up as a default rather than as an absence:
#   ServiceType 16 = SERVICE_WIN32_OWN_PROCESS
#   StartType    2 = SERVICE_AUTO_START — without it the agent stops reporting
#                    at the next reboot, and a silent host looks exactly like a
#                    host whose certificates have not changed.
row="$(printf '%s' "$install" | head -1)"
type_col="$(printf '%s' "$row" | cut -f4)"
start_col="$(printf '%s' "$row" | cut -f5)"
[ "$type_col" = "16" ] || { echo "  FAIL  service type is $type_col, want 16 (own process)" >&2; fail=1; }
[ "$start_col" = "2" ]  || { echo "  FAIL  start type is $start_col, want 2 (automatic)" >&2; fail=1; }
[ "$type_col" = "16" ] && [ "$start_col" = "2" ] && echo "  ok    own-process service, automatic start"

control="$(rows ServiceControl)"
[ -n "$control" ] || {
  echo "  FAIL  nothing starts or removes the service; it would be registered and left stopped" >&2
  fail=1
}
check "the service is controlled on install and uninstall" "$control" "$SERVICE_NAME"

# THE NOTIFICATION-AREA ICON, and the three ways it is reached. Each is a row
# wixl could drop or mangle while still reporting success, and the shortcut in
# particular comes out ADVERTISED — targeting the feature, not the file — if it
# is declared inside its <File>.
check "the notification-area icon is in the package" "$(rows File)" "dtp-agent-tray.exe"

shortcut="$(rows Shortcut)"
check "a Start-menu shortcut is installed"          "$shortcut" "ProgramMenuFolder"
check "the shortcut targets the icon's file itself" "$shortcut" "[INSTALLDIR]dtp-agent-tray.exe"

check "the icon starts at every user's sign-in" "$(rows Registry)" 'CurrentVersion\Run'
check "sign-in starts honour each user's opt-out" "$(rows Registry)" "--autostart"

# EXACTLY TWO CUSTOM ACTIONS, both running the icon's own binary. Anything else
# here would be the first thing in this package able to run arbitrary code at
# uninstall, which is how a state directory gets deleted.
actions="$(rows CustomAction)"
names="$(printf '%s\n' "$actions" | cut -f1 | sort | tr '\n' ' ')"
if [ "$names" = "LaunchTray StopTray " ]; then
  echo "  ok    the only custom actions are LaunchTray and StopTray"
else
  echo "  FAIL  custom actions are: $names (want exactly LaunchTray StopTray)" >&2
  fail=1
fi
#   3154 = exe from an installed file (18) + ignore exit code (64)
#        + async (128) + deferred (1024) + not impersonated (2048): runs as
#        SYSTEM, inside the transaction, where it can reach every session.
#    210 = exe from an installed file (18) + ignore (64) + async (128),
#        immediate: runs as the person installing, after the transaction.
for want in "StopTray	3154" "LaunchTray	210"; do
  name="${want%%	*}"
  got="$(printf '%s\n' "$actions" | awk -F'\t' -v n="$name" '$1==n {print $2}')"
  if [ "$got" = "${want##*	}" ]; then
    echo "  ok    $name has type $got"
  else
    echo "  FAIL  $name has type '${got}', want ${want##*	}" >&2
    fail=1
  fi
done

# THE ORDER, read off the built table, because wixl's After= is broken: it
# appends the action at the end whatever it names. A deferred action after
# InstallFinalize fails the whole install, on Windows, where nobody here sees it.
seq="$(rows InstallExecuteSequence)"
at() { printf '%s\n' "$seq" | awk -F'\t' -v n="$1" '$1==n {print $3}'; }
init="$(at InstallInitialize)"; stop="$(at StopTray)"; removefiles="$(at RemoveFiles)"
final="$(at InstallFinalize)"; launch="$(at LaunchTray)"
if [ -n "$stop" ] && [ "$init" -lt "$stop" ] && [ "$stop" -lt "$removefiles" ]; then
  echo "  ok    StopTray runs inside the transaction, before files are removed ($init < $stop < $removefiles)"
else
  echo "  FAIL  StopTray is at '${stop}'; it must sit between InstallInitialize ($init) and RemoveFiles ($removefiles)" >&2
  fail=1
fi
if [ -n "$launch" ] && [ "$launch" -gt "$final" ]; then
  echo "  ok    LaunchTray runs after the install has committed ($launch > $final)"
else
  echo "  FAIL  LaunchTray is at '${launch}'; it must come after InstallFinalize ($final)" >&2
  fail=1
fi

# Removal must not reach the state directory: it holds the keypair DTP has
# already approved, and deleting it would turn every reinstall in an estate into
# a fresh round of approvals. The MSI leaves it alone by never naming it.
remove="$(rows RemoveFile)"
if printf '%s' "$remove" | grep -qiE 'ProgramData|DTP\\agent'; then
  echo "  FAIL  the package removes files under the agent's state directory" >&2
  fail=1
else
  echo "  ok    nothing removes the agent's state directory"
fi

exit "$fail"
