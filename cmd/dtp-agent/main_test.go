package main

import "testing"

// Holding the window for a command a schedule runs would hang that schedule
// forever, so the list is pinned here rather than left to a comment.
func TestOnlyTheCommandsAPersonReadsHoldTheWindow(t *testing.T) {
	for _, args := range [][]string{{}, {"status"}} {
		if !holdsItsWindow(args) {
			t.Errorf("%v should hold its window: a person started it to read it", args)
		}
	}
	for _, args := range [][]string{{"run"}, {"run", "--once"}, {"scan"}, {"enroll"}, {"service"}, {"version"}, {"help"}} {
		if holdsItsWindow(args) {
			t.Errorf("%v holds its window; started by a schedule it would wait forever", args)
		}
	}
}
