//go:build !windows

package main

import (
	"errors"
	"runtime"
)

// The command exists on every platform so that `dtp-agent service` answers
// rather than printing "unknown command" — the binary is the same everywhere,
// and somebody following a Windows instruction on a Linux box deserves to be
// told where the schedule actually lives.
//
// Windows is the only platform that needs the agent to stay resident: its
// service manager has no timer, so the agent keeps its own schedule there.
// systemd and launchd run it as a oneshot on theirs, which is why there is
// nothing for this to do here.
func runService(string) error {
	if runtime.GOOS == "darwin" {
		return errors.New("macOS schedules this agent with launchd, not a resident service:\n" +
			"  sudo launchctl load /Library/LaunchDaemons/com.ssl.dtp-agent.plist")
	}
	return errors.New("Linux schedules this agent with systemd, not a resident service:\n" +
		"  sudo systemctl enable --now dtp-agent.timer")
}
