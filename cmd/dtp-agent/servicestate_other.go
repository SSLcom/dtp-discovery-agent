//go:build !windows

package main

// No resident service on these platforms — systemd and launchd hold the
// schedule — so `dtp-agent status` has nothing to report here. An empty string
// means "say nothing", rather than a line claiming a service is missing on a
// host that was never meant to have one.
func serviceState() string { return "" }
