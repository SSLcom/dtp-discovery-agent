//go:build windows

package collect

import "io/fs"

// fileOwner is not reported on Windows.
//
// The ACL, not a POSIX owner, is what decides access there, and reducing one to
// the other would put a value in the portfolio that reads like a Unix owner and
// is not. Better an empty column than a misleading one; the Windows certificate
// store collector reports store location instead, which is the meaningful
// equivalent.
func fileOwner(_ fs.FileInfo) string { return "" }
