//go:build windows

package main

import (
	"testing"

	"github.com/SSLcom/dtp-discovery-agent/internal/tray"
)

// CreateIconFromResourceEx returns a null handle for data it does not accept,
// and a null icon is an INVISIBLE one: the notification area keeps a click
// target with nothing drawn on it, and nothing reports an error.
func TestWindowsAcceptsEveryIconTheTrayDraws(t *testing.T) {
	for _, h := range []tray.Health{tray.Good, tray.Attention, tray.Problem, tray.Unknown} {
		for _, size := range []int{16, 20, 24, 32} {
			for _, dark := range []bool{true, false} {
				icon := iconFromPNG(tray.Icon(h, size, dark), size)
				if icon == 0 {
					t.Errorf("Windows rejected the health-%d icon at %d px (dark taskbar %v)", h, size, dark)
					continue
				}
				procDestroyIcon.Call(uintptr(icon))
			}
		}
	}
}
