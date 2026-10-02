//go:build !windows

// Command dtp-agent-tray is the agent's Windows notification-area icon. It
// builds everywhere so `go build ./...` and `go vet ./...` stay whole on every
// platform, and says so when run anywhere else.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "dtp-agent-tray is the Windows notification-area icon; on this platform use `dtp-agent status`.")
	os.Exit(2)
}
