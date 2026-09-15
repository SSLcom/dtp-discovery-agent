#!/bin/sh
set -e

# Stop the timer before the binary goes. Leaves /var/lib/dtp-agent — it holds
# the agent's keypair, and an operator reinstalling or upgrading should not
# silently lose the identity DTP has already approved. Removing the directory
# is a deliberate act: `rm -rf /var/lib/dtp-agent`, after revoking the agent.
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now dtp-agent.timer >/dev/null 2>&1 || true
  systemctl stop dtp-agent.service >/dev/null 2>&1 || true
fi
