//go:build windows

package collect

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The stores a server's own certificates are in.
//
// On Windows a certificate does not live in a file: IIS, SQL Server, RDP and
// WinRM all bind to a store entry. There is no PEM on the disk for a
// file-walking collector to find, which is why a Windows web server looks bare
// to every other source.
//
// ROOT and CA are deliberately absent. They are the machine's trust anchors,
// several hundred of them, and none is deployed on it.
var defaultWindowsStores = []string{
	`LocalMachine\My`,
	// IIS 8 and later put site certificates here, and a busy host keeps
	// hundreds in it while My holds only a handful.
	`LocalMachine\WebHosting`,
	`LocalMachine\Remote Desktop`,
	`CurrentUser\My`,
}

// Certificate context property ids. From wincrypt.h; x/sys/windows does not
// export them.
const (
	certKeyProvInfoPropID  = 2  // Present iff the machine holds the private key.
	certFriendlyNamePropID = 11 // What an administrator named it in the snap-in.
)

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
)

func readOSStores(ctx context.Context, only []string) ([]storeEntry, []storeFailure, error) {
	names := only
	if len(names) == 0 {
		names = defaultWindowsStores
	}

	var (
		entries  []storeEntry
		failures []storeFailure
	)
	for _, name := range names {
		if ctx.Err() != nil {
			return entries, failures, ctx.Err()
		}
		found, err := readWindowsStore(name)
		switch {
		case err == nil:
			entries = append(entries, found...)
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			// The store is not on this machine — WebHosting exists only where
			// IIS 8 or later is installed. Not a fault, exactly like a web
			// server that is not installed.
		default:
			failures = append(failures, storeFailure{Store: name, Err: err})
		}
	}
	return entries, failures, nil
}

func readWindowsStore(name string) ([]storeEntry, error) {
	location, store, err := splitWindowsStoreName(name)
	if err != nil {
		return nil, err
	}
	storeName, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		// READONLY because this agent does not write to a customer's machine,
		// and saying so to the API means a bug here cannot.
		location|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	defer func() { _ = windows.CertCloseStore(handle, 0) }()

	var (
		entries []storeEntry
		context *windows.CertContext
	)
	for {
		context, err = windows.CertEnumCertificatesInStore(handle, context)
		if context == nil {
			// The enumeration is finished. The final call reports
			// CRYPT_E_NOT_FOUND, which is the end of the store rather than a
			// failure to read it.
			break
		}
		if err != nil {
			return entries, fmt.Errorf("reading %s: %w", name, err)
		}

		// COPIED, not referenced. x509.ParseCertificate keeps the slice it was
		// given as cert.Raw, and this memory belongs to the certificate context
		// — which the NEXT call to CertEnumCertificatesInStore frees. Without
		// the copy, every certificate the agent reported would be pointing at
		// memory Windows had already reclaimed, and what it uploaded would be
		// whatever happened to be there.
		der := make([]byte, context.Length)
		copy(der, unsafe.Slice(context.EncodedCert, context.Length))

		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			// A store can hold something Go will not parse. One of those is not
			// a reason to abandon the rest of the store.
			continue
		}
		entries = append(entries, storeEntry{
			Store:         name,
			Certificate:   cert,
			HasPrivateKey: hasCertProperty(context, certKeyProvInfoPropID),
			FriendlyName:  certStringProperty(context, certFriendlyNamePropID),
		})
	}
	return entries, nil
}

func splitWindowsStoreName(name string) (uint32, string, error) {
	parts := strings.SplitN(name, `\`, 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("store name %q is not of the form Location\\Store", name)
	}
	switch strings.ToLower(parts[0]) {
	case "localmachine":
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, parts[1], nil
	case "currentuser":
		return windows.CERT_SYSTEM_STORE_CURRENT_USER, parts[1], nil
	default:
		return 0, "", fmt.Errorf("unknown store location %q in %q", parts[0], name)
	}
}

// hasCertProperty reports whether a certificate carries a property at all,
// which for CERT_KEY_PROV_INFO_PROP_ID is how Windows says the machine holds
// the matching private key. Only its presence is asked for; the property's
// contents are never read, and the key itself is not reachable from here.
func hasCertProperty(context *windows.CertContext, propID uint32) bool {
	var size uint32
	ret, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(context)), uintptr(propID), 0, uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(context)
	return ret != 0 && size > 0
}

func certStringProperty(context *windows.CertContext, propID uint32) string {
	var size uint32
	ret, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(context)), uintptr(propID), 0, uintptr(unsafe.Pointer(&size)))
	if ret == 0 || size == 0 {
		runtime.KeepAlive(context)
		return ""
	}

	// Allocated as uint16 rather than as bytes: the value is a UTF-16 string,
	// and a []byte is not guaranteed to be aligned for reading as one.
	buf := make([]uint16, (size+1)/2)
	ret, _, _ = procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(context)), uintptr(propID),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(context)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
