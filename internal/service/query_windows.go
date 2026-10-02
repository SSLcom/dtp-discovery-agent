//go:build windows

package service

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ErrNotInstalled is Query's answer on a machine where the service was never
// registered: someone who unzipped the archive instead of running the
// installer, which is the answer that explains why nothing is happening.
var ErrNotInstalled = errors.New("the service is not installed")

// Query asks the Service Control Manager what state the agent's service is in.
//
// WITH THE LEAST ACCESS THAT ANSWERS. mgr.Connect asks for full control of the
// service database, which an unelevated process does not hold — and the
// notification-area icon is always unelevated, as is an administrator's prompt
// under UAC. Connecting and querying status are granted to every interactive
// user, so this works from anywhere.
func Query() (svc.State, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(m)

	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return 0, err
	}
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return 0, ErrNotInstalled
		}
		return 0, err
	}
	defer windows.CloseServiceHandle(s)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &status); err != nil {
		return 0, err
	}
	return svc.State(status.CurrentState), nil
}
