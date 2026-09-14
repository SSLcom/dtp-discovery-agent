package collect

import (
	"context"
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// Bounds keep a scan from becoming the incident it was meant to prevent. This
// binary runs on machines nobody is watching; an unbounded walk of a host with
// an NFS mount and a 40 GB log directory is a support call at best.
type Bounds struct {
	Roots        []string
	MaxFileBytes int64
	MaxDepth     int
	MaxFiles     int
}

// Defaults chosen to find what is actually there without reading the whole
// disk. The roots are where TLS material lives on a Unix host; a member with an
// unusual layout adds their own rather than the agent guessing by walking `/`.
func DefaultBounds() Bounds {
	roots := []string{
		"/etc/ssl", "/etc/pki", "/etc/tls", "/etc/nginx", "/etc/apache2",
		"/etc/httpd", "/etc/haproxy", "/etc/letsencrypt", "/etc/ipsec.d",
		"/opt/*/ssl", "/usr/local/etc/ssl", "/var/lib/acme",
	}
	if runtime.GOOS == "windows" {
		roots = []string{`C:\ProgramData\ssl`, `C:\inetpub`}
	}
	return Bounds{
		Roots: roots,
		// A certificate file is kilobytes. Anything past this is a log, a
		// database, or a core dump that happens to end in .pem.
		MaxFileBytes: 1 << 20,
		MaxDepth:     8,
		MaxFiles:     50000,
	}
}

func (b Bounds) withDefaults() Bounds {
	d := DefaultBounds()
	if len(b.Roots) == 0 {
		b.Roots = d.Roots
	}
	if b.MaxFileBytes <= 0 {
		b.MaxFileBytes = d.MaxFileBytes
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = d.MaxDepth
	}
	if b.MaxFiles <= 0 {
		b.MaxFiles = d.MaxFiles
	}
	return b
}

// Extensions worth opening. Everything else is skipped without a read, which is
// what keeps the walk cheap.
var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true,
	".der": true, ".p12": true, ".pfx": true, ".chain": true, ".bundle": true,
}

func isPKCS12(ext string) bool { return ext == ".p12" || ext == ".pfx" }

// FS finds certificates in files.
type FS struct{ Bounds Bounds }

func (c *FS) Source() string { return SourceFile }

func (c *FS) Collect(ctx context.Context) Result {
	b := c.Bounds.withDefaults()
	res := Result{Source: SourceFile, Completed: true}
	seen := 0

	for _, root := range b.Roots {
		// A root may be a glob (/opt/*/ssl). Expanding here rather than walking
		// the parent keeps the bound meaningful.
		matches, err := filepath.Glob(root)
		if err != nil || len(matches) == 0 {
			if _, statErr := os.Stat(root); statErr == nil {
				matches = []string{root}
			} else {
				continue // A root that is not on this host is not an error.
			}
		}

		for _, dir := range matches {
			if err := c.walk(ctx, dir, b, &res, &seen); err != nil {
				// The walk itself failed — not one file within it. The sweep is
				// incomplete, so nothing this collector reports may be used to
				// mark a certificate absent.
				res.Completed = false
				res.Errors = append(res.Errors, Error{
					Collector: SourceFile, Location: dir, Error: err.Error(),
				})
			}
		}
	}
	return res
}

func (c *FS) walk(ctx context.Context, root string, b Bounds, res *Result, seen *int) error {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// One unreadable directory does not end the sweep, but it DOES mean
			// this collector did not see everything — so the run cannot
			// conclude anything is gone.
			res.Completed = false
			res.Errors = append(res.Errors, Error{
				Collector: SourceFile, Location: path, Error: err.Error(),
			})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth >= b.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// Symlinks are not followed: a link into /proc or a loop back up the
		// tree turns a bounded walk into an unbounded one, and the target is
		// either inside a root already or deliberately outside it.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !certExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if *seen >= b.MaxFiles {
			res.Completed = false
			return filepath.SkipAll
		}
		*seen++

		info, err := d.Info()
		if err != nil || info.Size() > b.MaxFileBytes || info.Size() == 0 {
			return nil
		}
		c.examine(path, info, res)
		return nil
	})
}

func (c *FS) examine(path string, info fs.FileInfo, res *Result) {
	data, err := os.ReadFile(path)
	if err != nil {
		res.Completed = false
		res.Errors = append(res.Errors, Error{
			Collector: SourceFile, Location: path, Error: err.Error(),
		})
		return
	}

	var parsed parse.Result
	if isPKCS12(strings.ToLower(filepath.Ext(path))) {
		// Only the empty password is attempted. Guessing at passwords is
		// something the agent should never do on a customer's machine, and a
		// bundle it cannot open is reported as unopened rather than attacked.
		parsed, err = parse.PKCS12(data, "")
	} else {
		parsed, err = parse.Certificates(data)
	}
	if err != nil || len(parsed.Certificates) == 0 {
		return // Not a certificate file. Silence is correct; this is not an error.
	}

	keyPath := ""
	if parsed.HadPrivateKey {
		keyPath = path // The key is IN this file.
	} else if sibling := siblingKey(path); sibling != "" {
		keyPath = sibling
	}

	// The LEAF is the observation; the rest is its chain. The server strips a
	// duplicate leaf from a supplied chain, but sending it clean is cheaper and
	// leaves less to disagree about.
	leaf := parsed.Certificates[0]
	res.Observations = append(res.Observations, Observation{
		CertificatePEM:     parse.EncodePEM([]*x509.Certificate{leaf}),
		ChainPEM:           parse.EncodePEM(parsed.Certificates[1:]),
		Source:             SourceFile,
		Location:           path,
		PrivateKeyPresent:  keyPath != "",
		PrivateKeyLocation: keyPath,
		FileMode:           fileMode(info),
		FileOwner:          fileOwner(info),
		ObservedAt:         time.Now().UTC(),
	})
}

func fileMode(info fs.FileInfo) string {
	return "0" + strings.TrimPrefix(info.Mode().Perm().String(), "-")
}

// siblingKey looks for the conventional key beside a certificate — site.pem
// next to site.key — WITHOUT reading it. Only the path is recorded.
func siblingKey(certPath string) string {
	base := strings.TrimSuffix(certPath, filepath.Ext(certPath))
	for _, candidate := range []string{base + ".key", base + "-key.pem", base + ".key.pem", base + "-privkey.pem"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	// Let's Encrypt's layout: fullchain.pem and privkey.pem in one directory.
	if privkey := filepath.Join(filepath.Dir(certPath), "privkey.pem"); filepath.Base(certPath) == "fullchain.pem" {
		if _, err := os.Stat(privkey); err == nil {
			return privkey
		}
	}
	return ""
}
