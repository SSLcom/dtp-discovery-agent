//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/SSLcom/dtp-discovery-agent/internal/service"
	"github.com/SSLcom/dtp-discovery-agent/internal/state"
)

// How long a scan already in flight is given to unwind after a stop, and how
// often the Service Control Manager is told we are still unwinding.
//
// THE PROGRESS REPORTS ARE NOT DECORATION. A service that stops answering while
// it shuts down is declared hung and killed, and what the administrator sees is
// "the service did not respond to the start or control request in a timely
// fashion" — which reads as a broken agent rather than as a scan closing its
// connections. The grace is bounded because a scan that will not let go must
// not hold up a reboot: nothing here writes to the host, so an interrupted scan
// costs one cycle of inventory and nothing else.
const (
	stopGrace = 20 * time.Second
	stopTick  = 2 * time.Second
)

// runService hands this process to the Windows Service Control Manager.
func runService(dir string) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("checking whether this process is a service: %w", err)
	}
	if !inService {
		// Asked for from a prompt. svc.Run would block trying to reach a
		// service control dispatcher that is not there and fail a minute later
		// with an error about a pipe, so say the useful thing instead.
		return errors.New("this command is run by the Windows Service Control Manager, not from a prompt\n" +
			"  start the service:  sc.exe start " + service.Name + "\n" +
			"  scan once, here:    dtp-agent run --once")
	}

	// Open the state directory FIRST. It is what fixes the ACL on a directory
	// holding this agent's private key, and doing it before the log means the
	// log file is created inside an already-protected directory rather than
	// one that is corrected a moment later.
	store, err := state.Open(dir)
	if err != nil {
		return err
	}

	log, err := service.OpenLog(service.LogPath(store.Dir()), 0)
	if err != nil {
		return err
	}
	defer log.Close()

	log.Printf("service starting: dtp-agent %s, state %s", Version, store.Dir())
	err = svc.Run(service.Name, &handler{dir: store.Dir(), log: log})
	if err != nil {
		log.Printf("service failed: %v", err)
		return err
	}
	log.Printf("service stopped")
	return nil
}

type handler struct {
	dir string
	log *service.Log
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 10_000}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		// The scheduler, and the reason it is a separate package: it is the
		// judgement in this file and none of it is Windows-specific, so it is
		// tested on every platform instead of only on the one it ships to.
		_ = service.New(h.log.Printf).Run(ctx, h.enrolled, h.scan)
	}()

	// RUNNING IS REPORTED BEFORE THE FIRST SCAN, not after it. The first scan
	// waits out a boot delay of several minutes, and a service that has not
	// said "running" by then is killed as failed to start.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case <-finished:
			// The loop ends only when its context is cancelled, so reaching
			// here without a stop request means something we did not ask for
			// ended it. Report the stop rather than leaving the manager
			// believing a process that has given up is still working.
			h.log.Printf("the scan loop ended on its own; stopping")
			status <- svc.Status{State: svc.StopPending}
			return false, 0

		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				h.log.Printf("stop requested")
				cancel()
				h.drain(finished, status)
				return false, 0
			default:
				// Anything else is ignored. An unrecognised control is not a
				// reason to take a host out of the inventory.
			}
		}
	}
}

func (h *handler) drain(finished <-chan struct{}, status chan<- svc.Status) {
	deadline := time.After(stopGrace)
	for checkpoint := uint32(1); ; checkpoint++ {
		status <- svc.Status{
			State:      svc.StopPending,
			CheckPoint: checkpoint,
			WaitHint:   uint32(3 * stopTick / time.Millisecond),
		}
		select {
		case <-finished:
			return
		case <-deadline:
			h.log.Printf("a scan was still running after %s; stopping anyway", stopGrace)
			return
		case <-time.After(stopTick):
		}
	}
}

// enrolled is asked before every scan, not once at startup: on Windows the
// normal order is install, start, THEN enroll, so the service is already
// running when a member first tells it who it belongs to.
func (h *handler) enrolled() bool {
	store, err := state.Open(h.dir)
	if err != nil {
		return false
	}
	_, err = store.LoadConfig()
	return err == nil
}

// scan does exactly what `dtp-agent run` does, including waiting out a pending
// approval rather than giving up for an hour — the service is already resident,
// and an admin who approves an agent should not watch nothing happen.
func (h *handler) scan(ctx context.Context) error {
	out := reporter{info: h.log.Printf, warn: h.log.Printf}
	return reportOnce(ctx, h.dir, nil, nil, false, out)
}
