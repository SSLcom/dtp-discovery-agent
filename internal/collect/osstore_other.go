//go:build !windows && !darwin

package collect

import (
	"context"
	"errors"
)

// errNoOSStore is the honest answer on a platform where there is no operating
// system certificate store to read.
//
// Linux has no such thing. What it has is /etc/ssl/certs — files, which the
// filesystem collector already reads, and which are a trust bundle rather than
// a place a service keeps the certificate it serves. Reporting them here as an
// "OS store" would duplicate every finding under a second source and give a
// member two rows to reconcile for one certificate.
var errNoOSStore = errors.New("this platform has no operating system certificate store")

func readOSStores(context.Context, []string) ([]storeEntry, []storeFailure, error) {
	return nil, nil, errNoOSStore
}
