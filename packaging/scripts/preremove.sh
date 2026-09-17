#!/bin/sh
set -e

# REMOVAL ONLY — NEVER ON UPGRADE.
#
# This one script is installed as both Debian's `prerm` and RPM's `%preun`, and
# BOTH run on upgrade as well as removal. Disabling the timer unconditionally
# means a routine `apt upgrade` stops an enrolled fleet reporting, nothing
# re-enables it, and nothing anywhere errors: the hosts simply go quiet and
# their portfolio entries stay exactly as they were, looking healthy. That is
# the precise failure the agent's staleness reporting exists to catch, arriving
# as a self-inflicted wound.
#
# The two packagers say "this is a removal" differently:
#
#   Debian prerm   $1 = remove | purge | upgrade | deconfigure | failed-upgrade
#   RPM   %preun   $1 = 0 on the final erase, >= 1 when an upgrade is in flight
#
# Anything this script does not recognise is treated as an UPGRADE, i.e. it does
# nothing. The two mistakes are not symmetric: failing to disable on a genuine
# removal leaves a timer whose binary is gone, which systemd complains about
# loudly and a person notices; disabling on an upgrade is silent and takes the
# fleet's reporting with it.
case "${1:-}" in
  remove|purge|0)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now dtp-agent.timer >/dev/null 2>&1 || true
      systemctl stop dtp-agent.service >/dev/null 2>&1 || true
    fi
    ;;
  *)
    # An upgrade. Leave the timer exactly as the operator set it — its enabled
    # state survives the package being replaced, and postinstall's
    # daemon-reload picks up any change to the unit files.
    ;;
esac

# /var/lib/dtp-agent is never touched here. It holds the agent's keypair — the
# identity DTP has already approved — and an operator upgrading or reinstalling
# should not silently have to get every host admitted again.
#
# dpkg reclaims the package-owned directory on removal ONLY when it is empty,
# which is to say only when there was no enrollment to lose; a host that ever
# ran keeps its key through both `remove` and `purge`. Verified, not assumed —
# see script/test-package-lifecycle.sh. Discarding the identity is a deliberate
# act: `rm -rf /var/lib/dtp-agent`, after revoking the agent in DTP.
