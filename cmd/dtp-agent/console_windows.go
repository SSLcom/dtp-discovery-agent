//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// ownsConsole reports whether this process is alone on its console — which is
// what Windows does when a console program is started from Explorer, a
// shortcut, or an elevation prompt: it creates a console for the process and
// destroys it the instant the process exits.
//
// WHY IT MATTERS. Double-clicking dtp-agent.exe printed the usage and closed
// the window before anyone could read it, and to a member who had just run the
// installer that looked exactly like the agent disappearing. Started from a
// prompt there is always a second process on the console — the shell — so this
// is false wherever a person or a script is already reading the output, and
// the behaviour there does not change at all.
//
// A service has no console, and the call fails: also false.
func ownsConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// holdConsole keeps a console Windows made for this process open until the
// person reading it is done.
func holdConsole() {
	fmt.Print("\nPress Enter to close this window.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
