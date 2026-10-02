//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The slice of user32 and shell32 the icon needs, which x/sys does not wrap.
// Called directly rather than through a systray library: those either need cgo,
// which would end the agent's single static binary, or pull in a GUI toolkit
// several times the size of the agent for one icon and one menu.

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procGetMessageW                   = user32.NewProc("GetMessageW")
	procTranslateMessage              = user32.NewProc("TranslateMessage")
	procDispatchMessageW              = user32.NewProc("DispatchMessageW")
	procPostQuitMessage               = user32.NewProc("PostQuitMessage")
	procPostMessageW                  = user32.NewProc("PostMessageW")
	procRegisterWindowMessageW        = user32.NewProc("RegisterWindowMessageW")
	procSetTimer                      = user32.NewProc("SetTimer")
	procCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	procAppendMenuW                   = user32.NewProc("AppendMenuW")
	procTrackPopupMenu                = user32.NewProc("TrackPopupMenu")
	procDestroyMenu                   = user32.NewProc("DestroyMenu")
	procSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	procGetCursorPos                  = user32.NewProc("GetCursorPos")
	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procCreateIconFromResourceEx      = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon                   = user32.NewProc("DestroyIcon")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procChangeWindowMessageFilterEx   = user32.NewProc("ChangeWindowMessageFilterEx")
	procShellNotifyIconW              = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmNull        = 0x0000
	wmTimer       = 0x0113
	wmContextMenu = 0x007B
	wmLButtonUp   = 0x0202
	wmUser        = 0x0400
	wmApp         = 0x8000

	// The message the notification area sends this window about its icon.
	wmTrayCallback = wmApp + 1

	ninSelect           = wmUser + 0
	ninKeySelect        = wmUser + 1
	ninBalloonUserClick = wmUser + 5

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4

	nifMessage  = 0x01
	nifIcon     = 0x02
	nifTip      = 0x04
	nifInfo     = 0x10
	nifShowTip  = 0x80
	niifInfo    = 0x01
	niifWarning = 0x02

	notifyIconVersion4 = 4

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	smCxSmIcon = 49
	smCySmIcon = 50

	swShowNormal = 1

	msgfltAllow = 1
)

// NOTIFYICONDATAW. Go lays the fields out with the same natural alignment as
// the C declaration, so the size Windows checks in cbSize comes out right on
// both 64-bit architectures.
type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

func utf16Into(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func shellNotifyIcon(message uint32, data *notifyIconData) bool {
	r, _, _ := procShellNotifyIconW.Call(uintptr(message), uintptr(unsafe.Pointer(data)))
	return r != 0
}

func systemMetric(index int) int {
	r, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(r)
}

// iconFromPNG turns a PNG into an icon handle. Windows has accepted PNG data as
// an icon image since Vista; 0x00030000 is the icon format version it expects.
func iconFromPNG(data []byte, size int) windows.Handle {
	if len(data) == 0 {
		return 0
	}
	r, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		1, 0x00030000, uintptr(size), uintptr(size), 0)
	return windows.Handle(r)
}

func appendMenu(menu uintptr, flags uint32, id uintptr, text string) {
	var p *uint16
	if text != "" {
		p, _ = windows.UTF16PtrFromString(text)
	}
	procAppendMenuW.Call(menu, uintptr(flags), id, uintptr(unsafe.Pointer(p)))
}

// allowFromExplorer lets the shell's messages through to this window even when
// this process runs at a higher integrity level than Explorer — which it does
// when the installer starts it, because the installer is elevated.
//
// WITHOUT THIS THE ICON IS DEAD TO THE MOUSE. User Interface Privilege Isolation
// drops messages sent upward in integrity, so Explorer's notifications about
// clicks never arrive: the icon appears, and nothing happens when it is
// clicked, until the user signs out and the unelevated copy takes over.
func allowFromExplorer(h windows.HWND, messages ...uint32) {
	for _, m := range messages {
		procChangeWindowMessageFilterEx.Call(uintptr(h), uintptr(m), msgfltAllow, 0)
	}
}
