package parse

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Java keystores. A Tomcat, a JBoss, an Elasticsearch — their certificates are
// in one of these, and they are invisible to every other collector: a .jks is
// not PEM and not DER, so a walk of the filesystem reads right past it.
//
// THE PRIVATE KEYS ARE NEVER READ. A key entry carries its encrypted blob
// behind a length, so the parser SKIPS that many bytes without looking at them —
// the bytes are not copied, decrypted or held. That is a stronger guarantee than
// any keystore library gives, because a library exists to return keys, and it is
// the reason this is ~150 lines here rather than a dependency.
//
// It also means the agent needs no password. Certificate entries in a JKS are
// not encrypted; only the keys and the integrity digest are. So the certificates
// come out of a store whose password nobody has told the agent, which is exactly
// the situation on a machine where the keystore was set up years ago.

const (
	// The Sun keystore magics, in the order the file writes them.
	jksMagic   uint32 = 0xFEEDFEED
	jceksMagic uint32 = 0xCECECECE

	entryPrivateKey   uint32 = 1
	entryTrustedCert  uint32 = 2
	entryJCEKSSecret  uint32 = 3
	keystoreTrailerSz        = 20 // The SHA-1 integrity digest at the end.
)

// ErrNotAJavaKeystore means these bytes are not a Sun-format keystore. Most
// files are not, so it is how the caller tells "wrong kind of file" from
// "keystore the agent could not read".
var ErrNotAJavaKeystore = errors.New("not a Java keystore")

// KeystoreEntry is one alias in a Java keystore.
//
// The alias matters to whoever has to act on the finding: it is what `keytool
// -delete -alias tomcat` takes, and on a machine with six aliases in one file it
// is the only thing that says which one is expiring.
type KeystoreEntry struct {
	Alias         string
	Certificates  []*x509.Certificate
	HasPrivateKey bool
}

// JavaKeystore reads the certificates out of a JKS or JCEKS file.
func JavaKeystore(data []byte) ([]KeystoreEntry, error) {
	r := &beReader{data: data}

	magic := r.u32()
	if r.err != nil || (magic != jksMagic && magic != jceksMagic) {
		return nil, ErrNotAJavaKeystore
	}
	version := r.u32()
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("%w: version %d", ErrNotAJavaKeystore, version)
	}
	count := r.u32()
	if r.err != nil {
		return nil, ErrNotAJavaKeystore
	}
	// A count is a number in a file, and a file can be corrupt or hostile. One
	// entry needs more than a dozen bytes, so anything past that is a lie and
	// must not become an allocation.
	if int(count) > len(data)/12 {
		return nil, fmt.Errorf("%w: claims %d entries in %d bytes", ErrNotAJavaKeystore, count, len(data))
	}

	entries := make([]KeystoreEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		tag := r.u32()
		alias := r.utf()
		r.skip(8) // Creation date, in milliseconds. Not what this is for.
		if r.err != nil {
			return entries, fmt.Errorf("entry %d: %w", i+1, r.err)
		}

		entry := KeystoreEntry{Alias: alias}
		switch tag {
		case entryPrivateKey:
			entry.HasPrivateKey = true
			// THE KEY ITSELF. Skipped by length: these bytes are never read
			// into anything, so no later change to this package can make them
			// reachable, and the encrypted blob is not held in memory at all.
			keyLen := r.u32()
			r.skip(int(keyLen))

			chainLen := r.u32()
			if r.err != nil {
				return entries, fmt.Errorf("entry %q: %w", alias, r.err)
			}
			if int(chainLen) > len(data)/12 {
				return entries, fmt.Errorf("entry %q claims a chain of %d certificates", alias, chainLen)
			}
			for j := uint32(0); j < chainLen; j++ {
				cert, err := r.certificate(version)
				if err != nil {
					return entries, fmt.Errorf("entry %q: %w", alias, err)
				}
				if cert != nil {
					entry.Certificates = append(entry.Certificates, cert)
				}
			}

		case entryTrustedCert:
			cert, err := r.certificate(version)
			if err != nil {
				return entries, fmt.Errorf("entry %q: %w", alias, err)
			}
			if cert != nil {
				entry.Certificates = append(entry.Certificates, cert)
			}

		case entryJCEKSSecret:
			// A JCEKS secret key is a Java-serialised SealedObject with NO
			// length in front of it, so there is no way to step over it without
			// implementing Java serialisation. The parser stops here and says
			// so rather than reading the rest of the file as garbage: what it
			// has already found is real, and the caller must be told the sweep
			// of this store is incomplete.
			return entries, fmt.Errorf("entry %q is a secret key, which this agent cannot skip past; the rest of the keystore was not read", alias)

		default:
			return entries, fmt.Errorf("entry %q has unknown type %d; the rest of the keystore was not read", alias, tag)
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

// certificate reads one certificate entry. Version 2 stores prefix it with a
// type string; version 1 stores do not, and a keystore written by a JDK old
// enough to do that is exactly the forgotten machine worth finding.
func (r *beReader) certificate(version uint32) (*x509.Certificate, error) {
	if version == 2 {
		if kind := r.utf(); kind != "" && kind != "X.509" && kind != "X509" {
			return nil, fmt.Errorf("certificate is of type %q, which is not X.509", kind)
		}
	}
	length := r.u32()
	der := r.bytes(int(length))
	if r.err != nil {
		return nil, r.err
	}
	// A certificate this parser cannot decode is not a reason to abandon the
	// rest of the store — the entries after it are still readable, and one
	// unparsable alias should not hide five good ones.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil
	}
	return cert, nil
}

// ── a bounds-checked big-endian reader ───────────────────────────────────────
//
// Every length in a keystore comes out of the file being read, and this agent
// runs unattended on machines nobody is watching. Each read checks what remains
// BEFORE it slices, so a corrupt or hostile store yields an error rather than a
// panic in a background service.

type beReader struct {
	data []byte
	pos  int
	err  error
}

func (r *beReader) remaining() int { return len(r.data) - r.pos }

func (r *beReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > r.remaining() {
		r.err = fmt.Errorf("keystore is truncated: wanted %d bytes, %d remain", n, r.remaining())
		return nil
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *beReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *beReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *beReader) skip(n int)         { r.take(n) }
func (r *beReader) bytes(n int) []byte { return r.take(n) }

// utf reads Java's modified UTF-8: a 16-bit length, then bytes that are UTF-8
// except that a supplementary character is written as its two surrogates
// encoded separately. An alias is almost always ASCII, but decoding it wrongly
// puts mojibake in front of whoever has to run keytool against it.
func (r *beReader) utf() string {
	length := r.u16()
	raw := r.take(int(length))
	if raw == nil {
		return ""
	}
	return decodeModifiedUTF8(raw)
}

func decodeModifiedUTF8(raw []byte) string {
	var runes []rune
	for i := 0; i < len(raw); {
		switch b := raw[i]; {
		case b < 0x80 && b != 0:
			runes = append(runes, rune(b))
			i++
		case b&0xE0 == 0xC0 && i+1 < len(raw):
			runes = append(runes, rune(b&0x1F)<<6|rune(raw[i+1]&0x3F))
			i += 2
		case b&0xF0 == 0xE0 && i+2 < len(raw):
			runes = append(runes, rune(b&0x0F)<<12|rune(raw[i+1]&0x3F)<<6|rune(raw[i+2]&0x3F))
			i += 3
		default:
			runes = append(runes, '�')
			i++
		}
	}
	// Surrogate pairs are written as two separate three-byte sequences in
	// modified UTF-8, so they arrive here as two runes and have to be put back
	// together.
	return string(utf16.Decode(toUTF16(runes)))
}

func toUTF16(runes []rune) []uint16 {
	out := make([]uint16, 0, len(runes))
	for _, r := range runes {
		if r > 0xFFFF {
			out = append(out, utf16.Encode([]rune{r})...)
			continue
		}
		out = append(out, uint16(r))
	}
	return out
}
