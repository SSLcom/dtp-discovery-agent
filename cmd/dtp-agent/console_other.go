//go:build !windows

package main

// A Unix terminal belongs to the shell that started the program, and outlives
// it. There is no window to hold open.
func ownsConsole() bool { return false }

func holdConsole() {}
