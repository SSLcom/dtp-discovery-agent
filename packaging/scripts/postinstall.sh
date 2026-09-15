#!/bin/sh
set -e

# Make systemd aware of the units. DELIBERATELY DOES NOT ENABLE OR START THEM:
# the agent has no account id or enrollment token until a member runs
# `dtp-agent enroll`, so a timer started here would do nothing but log a
# failure every hour. Installing is not enrolling.
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Belt and braces on the state directory. The package declares the mode, but an
# upgrade over a directory an older version or an operator created leaves that
# directory's own mode in place — and it holds the agent's private key.
if [ -d /var/lib/dtp-agent ]; then
  chmod 0700 /var/lib/dtp-agent || true
fi

cat <<'MSG'

dtp-agent installed. It is not running yet — enrol it first:

  dtp-agent enroll --server https://YOUR-DTP --account YOUR-ACCOUNT-ID --token dtpd_...
  systemctl enable --now dtp-agent.timer

Check what it would report, without reporting anything:

  dtp-agent scan

MSG
