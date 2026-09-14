//go:build !windows

package collect

import (
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
)

// fileOwner resolves the owning user's name, falling back to the numeric uid.
//
// The name is looked up rather than reported raw because "root" means something
// to the person reading the portfolio and "0" means slightly less — but the
// lookup fails on a host using LDAP/SSSD without a local entry, and a uid is a
// better answer than an empty column.
func fileOwner(info fs.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}
