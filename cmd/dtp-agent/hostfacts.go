package main

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

func osName() string   { return runtime.GOOS }
func archName() string { return runtime.GOARCH }

// machineID is the host's own stable identifier. It exists so DTP can spot the
// same machine re-registering after a reinstall — the KEY is the identity, but
// a key changes when a host is rebuilt and this does not.
//
// Self-reported and never trusted for authorization. Empty is a fine answer:
// a container without /etc/machine-id is not a problem to solve here.
func machineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if raw, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(raw)); id != "" {
				return id
			}
		}
	}
	return ""
}

// osVersion reads the distribution's own name for itself. Best-effort: this is
// shown to a human deciding whether to admit a machine, not parsed by anything.
func osVersion() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if name, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(name, `"`)
		}
	}
	return ""
}
