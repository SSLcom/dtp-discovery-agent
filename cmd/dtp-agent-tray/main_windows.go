//go:build windows

// Command dtp-agent-tray is the DTP agent's icon in the Windows notification
// area: what the service is doing, at a glance, for whoever is signed in.
//
// WHY IT EXISTS. The agent is a service and a command-line tool, so installing
// it showed a progress bar and then nothing at all — and a member who has just
// run an installer and seen nothing concludes it failed. This is the visible
// part: it appears when the install finishes, says whether the machine still
// needs enrolling, and goes on saying whether it is reporting.
//
// IT IS READ-ONLY AND UNPRIVILEGED. It runs as the signed-in user, unelevated,
// and holds none of the agent's credentials. It reads two things — the state
// the Service Control Manager reports, and the summary the service publishes
// for exactly this purpose (internal/state/public.go) — and anything that
// needs more, like the full status, it hands to `dtp-agent status` through an
// elevation prompt the member can see and refuse.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"

	"github.com/SSLcom/dtp-discovery-agent/internal/service"
	"github.com/SSLcom/dtp-discovery-agent/internal/state"
	"github.com/SSLcom/dtp-discovery-agent/internal/tray"
)

// Version is stamped at build time, as the agent's is.
var Version = "dev"

const (
	// Where "How to enroll…" goes. The README's Windows section carries the
	// PowerShell line that works, and why the obvious one does not.
	enrollDocsURL = "https://github.com/SSLcom/dtp-discovery-agent#windows"

	// The per-user opt-out. The installer starts the icon at every sign-in for
	// every user; this is how one user says not for me. HKCU, so it is theirs
	// alone and needs no elevation to change.
	prefsKey       = `Software\SSL.com\DTP Agent`
	prefShowAtSign = "ShowTrayAtSignIn"

	// How often the icon looks again. The service writes on every phase change
	// and at least once a minute while it waits for enrollment, so this is
	// close enough to live without being a load anyone could measure.
	refreshEvery = 10 * time.Second

	timerID = 1
)

const (
	cmdStatus = iota + 1
	cmdOpenDTP
	cmdEnrollHelp
	cmdShowAtSignIn
	cmdExit
)

var (
	hwnd           windows.HWND
	taskbarCreated uint32
	nid            notifyIconData
	added          bool
	icons          = map[tray.Health]windows.Handle{}
	current        tray.View
	haveView       bool
	installedNote  bool
)

func main() {
	autostart := flag.Bool("autostart", false, "started at sign-in: honour this user's opt-out")
	installed := flag.Bool("installed", false, "started by the installer: say so once")
	stopAll := flag.Bool("stop-all", false, "end every running copy of the icon (the installer, before it replaces this file)")
	printView := flag.Bool("print", false, "print what the icon would show, and exit")
	handedOff := flag.Bool("handed-off", false, "started by an elevated copy of itself, as the desktop's own user")
	flag.Parse()

	switch {
	case *stopAll:
		stopOthers()
		return
	case *printView:
		v := describe()
		fmt.Printf("dtp-agent-tray %s\nhealth    %d\n%s\n", Version, v.Health, v.Headline)
		for _, d := range v.Details {
			fmt.Println("  " + d)
		}
		return
	case *autostart && !showAtSignIn():
		return
	}

	// THE ICON NEVER RUNS ELEVATED. The installer is elevated, so the copy it
	// starts would be too — and on a machine where an administrator typed
	// their password into a standard user's UAC prompt, that copy would sit on
	// the USER'S desktop holding the ADMINISTRATOR'S token until sign-out:
	// "Open DTP" would start a browser as the administrator, and "Show full
	// status" would not even ask. So an elevated copy starts the icon again
	// as whoever owns the desktop it is on, and leaves.
	//
	// --handed-off stops that becoming a loop where the desktop itself runs
	// elevated (UAC switched off), which has no lower token to hand to.
	if windows.GetCurrentProcessToken().IsElevated() && !*handedOff {
		args := "--handed-off"
		if *installed {
			args += " --installed"
		}
		handOffToShell(args)
		return
	}

	// Session 0 has no desktop and no notification area: an installer run
	// there by a configuration tool. Nothing to show, and nobody to show it to.
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) == nil && session == 0 {
		return
	}

	// One icon per session. Started from the Start menu while one is already
	// running, the second copy simply leaves. ACCESS_DENIED means the mutex
	// exists and belongs to a token this one cannot open — still "running".
	//
	// KNOWN LIMITATION: any process in the session can create this name first
	// and keep the icon away. It can only take away the icon, which the same
	// user could close from its own menu, so it is not worth a DACL.
	if h, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Local\SSL.com-DTPAgentTray`)); err == windows.ERROR_ALREADY_EXISTS || (h == 0 && err != nil) {
		return
	}
	installedNote = *installed

	// Window messages belong to the thread that created the window.
	runtime.LockOSThread()

	// Per-monitor DPI awareness, so the icon is drawn at the size the display
	// actually wants rather than drawn at 16 px and stretched blurry. Absent
	// before Windows 10 1703, where the icon is merely less sharp.
	if procSetProcessDpiAwarenessContext.Find() == nil {
		procSetProcessDpiAwarenessContext.Call(^uintptr(3)) // PER_MONITOR_AWARE_V2 (-4)
	}

	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return err
	}
	className := windows.StringToUTF16Ptr("DTPAgentTray")
	wc := wndClassEx{
		WndProc:   windows.NewCallback(wndProc),
		Instance:  instance,
		ClassName: className,
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return err
	}

	// Explorer broadcasts this when it restarts, taking every notification
	// icon with it. Without handling it, the icon is gone until sign-out.
	taskbarCreated = registerWindowMessage("TaskbarCreated")

	// A real top-level window that is never shown, not a message-only one:
	// message-only windows do not receive broadcasts, and TaskbarCreated is one.
	r, _, err := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("DTP Agent"))),
		0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
	if r == 0 {
		return err
	}
	hwnd = windows.HWND(r)

	drawIcons()
	refresh()
	procSetTimer.Call(uintptr(hwnd), timerID, uintptr(refreshEvery/time.Millisecond), 0)

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	for _, icon := range icons {
		procDestroyIcon.Call(uintptr(icon))
	}
	return nil
}

// drawIcons makes one icon per health at the size and in the ink the taskbar
// wants now. Called again when either changes, so the old handles are freed.
func drawIcons() {
	size := systemMetric(smCxSmIcon)
	if size <= 0 {
		size = 16
	}
	dark := taskbarIsDark()
	for _, h := range []tray.Health{tray.Good, tray.Attention, tray.Problem, tray.Unknown} {
		if old := icons[h]; old != 0 {
			procDestroyIcon.Call(uintptr(old))
		}
		icons[h] = iconFromPNG(tray.Icon(h, size, dark), size)
	}
}

// taskbarIsDark reads the setting Windows itself uses for the taskbar's
// colour — SystemUsesLightTheme, which is separate from the APPS setting a
// user can set the other way. Absent (Windows 10 before 1903) means dark,
// which is what the taskbar was.
func taskbarIsDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("SystemUsesLightTheme")
	return err != nil || v == 0
}

func wndProc(h windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmTrayCallback:
		switch uint32(lParam & 0xffff) {
		case wmContextMenu, ninSelect, ninKeySelect:
			// Version 4 sends the anchor point in wParam, which is where the
			// menu belongs when the icon was chosen from the keyboard.
			showMenu(int32(int16(wParam&0xffff)), int32(int16((wParam>>16)&0xffff)))
		case ninBalloonUserClick:
			// The notification that says "click here for how to enroll" must
			// do exactly that, not open a menu.
			if current.NeedsEnrollment {
				_ = shellExecute("open", enrollDocsURL, "", "")
				break
			}
			var p point
			procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
			showMenu(p.X, p.Y)
		}
		return 0
	case wmTimer:
		refresh()
		return 0
	case wmSettingChange:
		// "ImmersiveColorSet" is what Windows broadcasts when the light/dark
		// setting flips. Redrawing on every settings broadcast instead would
		// be harmless but wasteful; on this one it is required, or a white
		// mark sits invisible on a taskbar that has just turned light.
		if lParam != 0 && windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&lParam))) == "ImmersiveColorSet" {
			drawIcons()
			if added {
				nid.UFlags = nifIcon
				nid.HIcon = icons[current.Health]
				shellNotifyIcon(nimModify, &nid)
			}
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(uintptr(h))
		return 0
	case wmDestroy:
		if added {
			shellNotifyIcon(nimDelete, &nid)
		}
		procPostQuitMessage.Call(0)
		return 0
	}
	if message == taskbarCreated && taskbarCreated != 0 {
		// Also broadcast on a DPI change, when the icon may still be there:
		// delete first, so the add cannot fail on a duplicate.
		if added {
			shellNotifyIcon(nimDelete, &nid)
		}
		added = false
		addIcon()
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(h), uintptr(message), wParam, lParam)
	return r
}

// describe reads both sources and decides.
func describe() tray.View {
	st, err := state.ReadPublicStatus(state.DefaultDir())
	return tray.Describe(serviceState(), st, err, time.Now())
}

func serviceState() tray.Service {
	s, err := service.Query()
	switch {
	case err == service.ErrNotInstalled:
		return tray.ServiceNotInstalled
	case err != nil:
		return tray.ServiceUnknown
	}
	switch s {
	case svc.Running:
		return tray.ServiceRunning
	case svc.StartPending:
		return tray.ServiceStarting
	case svc.StopPending:
		return tray.ServiceStopping
	case svc.Stopped:
		return tray.ServiceStopped
	default:
		return tray.ServiceUnknown
	}
}

func refresh() {
	v := describe()
	previous, had := current, haveView
	current, haveView = v, true

	if !added {
		// Kept trying for as long as it takes. At a first sign-in Explorer
		// can be minutes from ready, and a session with no shell at all was
		// turned away before the window existed.
		addIcon()
		return
	}

	nid.UFlags = nifIcon | nifTip | nifShowTip
	nid.HIcon = icons[v.Health]
	nid.SzTip = [128]uint16{}
	utf16Into(nid.SzTip[:], v.Tooltip())
	shellNotifyIcon(nimModify, &nid)

	// SPOKEN UP ONCE PER TRANSITION, not on every refresh. A notification
	// every ten seconds about the same failure is how people learn to turn
	// notifications off — and then the next, different, failure goes unseen.
	if had && v.Health == tray.Problem && previous.Health != tray.Problem {
		balloon(niifWarning, "DTP Agent needs attention", v.Headline)
	}
}

func addIcon() {
	nid = notifyIconData{
		HWnd:             hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip | nifShowTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            icons[current.Health],
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	utf16Into(nid.SzTip[:], current.Tooltip())
	if !shellNotifyIcon(nimAdd, &nid) && !shellNotifyIcon(nimModify, &nid) {
		return
	}
	added = true
	nid.UVersion = notifyIconVersion4
	shellNotifyIcon(nimSetVersion, &nid)

	if installedNote {
		installedNote = false
		text := current.Headline
		if current.NeedsEnrollment {
			text = "This machine is not enrolled yet. Click here for how to enroll it."
		}
		balloon(niifInfo, "DTP Agent is installed", text)
	}
}

func balloon(flags uint32, title, text string) {
	nid.UFlags = nifInfo
	nid.DwInfoFlags = flags
	nid.SzInfoTitle = [64]uint16{}
	nid.SzInfo = [256]uint16{}
	utf16Into(nid.SzInfoTitle[:], title)
	utf16Into(nid.SzInfo[:], text)
	shellNotifyIcon(nimModify, &nid)
}

func showMenu(x, y int32) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	appendMenu(menu, mfString|mfGrayed, 0, current.Headline)
	for _, d := range current.Details {
		appendMenu(menu, mfString|mfGrayed, 0, d)
	}
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, cmdStatus, "Show full status…")
	if current.ServerURL != "" {
		appendMenu(menu, mfString, cmdOpenDTP, "Open DTP")
	}
	if current.NeedsEnrollment {
		appendMenu(menu, mfString, cmdEnrollHelp, "How to enroll this machine…")
	}
	appendMenu(menu, mfSeparator, 0, "")
	signIn := uint32(mfString)
	if showAtSignIn() {
		signIn |= mfChecked
	}
	appendMenu(menu, signIn, cmdShowAtSignIn, "Show this icon at sign-in")
	appendMenu(menu, mfString, cmdExit, "Exit")

	// Both halves of a documented quirk: without the foreground call the menu
	// does not close when the user clicks elsewhere, and without the posted
	// null message it fails to open on every second click.
	procSetForegroundWindow.Call(uintptr(hwnd))
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmReturnCmd|tpmRightButton|tpmNoNotify,
		uintptr(x), uintptr(y), 0, uintptr(hwnd), 0)
	procPostMessageW.Call(uintptr(hwnd), wmNull, 0, 0)

	switch cmd {
	case cmdStatus:
		// ELEVATED, through the prompt, and that is the honest way round: the
		// full status reads the state directory, which is closed to this
		// process. The prompt says exactly what will run. The agent holds its
		// own console open when started this way — see console_windows.go.
		exe := siblingExe("dtp-agent.exe")
		_ = shellExecute("runas", exe, "status", filepath.Dir(exe))
	case cmdOpenDTP:
		_ = shellExecute("open", current.ServerURL, "", "")
	case cmdEnrollHelp:
		_ = shellExecute("open", enrollDocsURL, "", "")
	case cmdShowAtSignIn:
		setShowAtSignIn(!showAtSignIn())
	case cmdExit:
		procPostMessageW.Call(uintptr(hwnd), wmClose, 0, 0)
	}
}

func shellExecute(verb, file, args, dir string) error {
	var a, d *uint16
	if args != "" {
		a = windows.StringToUTF16Ptr(args)
	}
	if dir != "" {
		d = windows.StringToUTF16Ptr(dir)
	}
	// A refused elevation prompt comes back as ERROR_CANCELLED. That is the
	// member's answer, not a failure to report.
	return windows.ShellExecute(windows.Handle(hwnd), windows.StringToUTF16Ptr(verb), windows.StringToUTF16Ptr(file), a, d, swShowNormal)
}

func siblingExe(name string) string {
	self, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(self), name)
}

func registerWindowMessage(name string) uint32 {
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))))
	return uint32(r)
}

// showAtSignIn is this user's choice; unset means yes.
func showAtSignIn() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, prefsKey, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(prefShowAtSign)
	return err != nil || v != 0
}

func setShowAtSignIn(show bool) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, prefsKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	v := uint32(0)
	if show {
		v = 1
	}
	_ = k.SetDWordValue(prefShowAtSign, v)
}

// stopOthers ends every other running copy of THIS file, in every session.
//
// The installer runs it, as SYSTEM, before it replaces or removes the file.
// Without it, an upgrade on a machine where anybody is signed in finds the
// file in use and finishes only at the next reboot — and with no UI to say so,
// the member sees an old icon carrying on as if nothing had happened.
//
// MATCHED ON THE FULL PATH, not the name, so it ends this installation's icon
// and nothing else that happens to share a file name.
func stopOthers() {
	self, err := os.Executable()
	if err != nil {
		return
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	me := windows.GetCurrentProcessId()
	base := filepath.Base(self)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID == me || !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), base) {
			continue
		}
		p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(p, 0, &buf[0], &n) == nil &&
			strings.EqualFold(windows.UTF16ToString(buf[:n]), self) {
			// TerminateProcess only STARTS the end of a process, and the file
			// stays locked until it is over — so wait, or the installer finds
			// the file in use anyway and finishes only at a reboot. This is
			// run by every later upgrade too (as the OLD package's StopTray,
			// before the new files land), so it has to be right here.
			//
			// The icon it leaves behind lingers in the notification area until
			// the mouse passes over it; that is Windows, and it is harmless.
			if windows.TerminateProcess(p, 0) == nil {
				_, _ = windows.WaitForSingleObject(p, 5000)
			}
		}
		windows.CloseHandle(p)
	}
}

// handOffToShell starts this program again as the user who owns the desktop,
// with the token of the desktop's own shell — the token everything the user
// starts from the Start menu gets. Used only by an elevated copy, so it holds
// the impersonation privilege CreateProcessWithTokenW needs.
//
// Every failure is silent, and safely so: the icon then appears at the user's
// next sign-in, from the Run key, unelevated.
func handOffToShell(args string) {
	shell := windows.GetShellWindow()
	if shell == 0 {
		return
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(shell, &pid); err != nil || pid == 0 {
		return
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(p)

	var shellToken windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &shellToken); err != nil {
		return
	}
	defer shellToken.Close()

	var token windows.Token
	if err := windows.DuplicateTokenEx(shellToken,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return
	}
	defer token.Close()

	self, err := os.Executable()
	if err != nil {
		return
	}
	cmdline, err := windows.UTF16PtrFromString(windows.EscapeArg(self) + " " + args)
	if err != nil {
		return
	}
	si := windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	r, _, _ := procCreateProcessWithTokenW.Call(uintptr(token), 0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(self))),
		uintptr(unsafe.Pointer(cmdline)),
		0, 0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(filepath.Dir(self)))),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r != 0 {
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}
}
