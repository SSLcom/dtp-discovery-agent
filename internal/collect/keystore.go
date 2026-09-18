package collect

import (
	"context"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// KeystoreBounds is where to look for Java keystores, and how hard.
type KeystoreBounds struct {
	Roots        []string
	MaxFileBytes int64
	MaxDepth     int
	MaxFiles     int
}

// Where Java keeps its keystores. Deliberately narrower than the filesystem
// collector's roots: these are directories a JDK or a Java service owns, not
// places certificates happen to live, and a keystore outside them is reached by
// naming it rather than by the agent walking more of the disk.
func DefaultKeystoreBounds() KeystoreBounds {
	roots := []string{
		"/etc/ssl/certs/java", "/etc/pki/java", "/etc/pki/ca-trust/extracted/java",
		"/usr/lib/jvm", "/usr/java", "/opt/java", "/opt/jdk",
		// Java services that terminate TLS themselves. Each keeps its keystore
		// in its own configuration directory, which is why none of them are
		// under the filesystem collector's roots.
		"/etc/tomcat*", "/var/lib/tomcat*/conf", "/usr/share/tomcat*/conf",
		"/opt/tomcat*/conf", "/etc/elasticsearch", "/usr/share/elasticsearch/config",
		"/etc/opensearch", "/etc/kafka", "/opt/kafka/config", "/etc/solr",
		"/opt/*/conf", "/opt/*/config",
	}
	switch runtime.GOOS {
	case "windows":
		roots = []string{
			`C:\Program Files\Java`, `C:\Program Files\Apache Software Foundation`,
			`C:\ProgramData\*\conf`,
		}
	case "darwin":
		roots = append(roots,
			"/Library/Java/JavaVirtualMachines", "/opt/homebrew/opt/openjdk",
			"/usr/local/opt/openjdk")
	}
	return KeystoreBounds{
		Roots: roots,
		// A keystore with a few hundred certificates is well under this; a
		// cacerts is about 150 KB.
		MaxFileBytes: 8 << 20,
		MaxDepth:     6,
		MaxFiles:     5000,
	}
}

func (b KeystoreBounds) withDefaults() KeystoreBounds {
	d := DefaultKeystoreBounds()
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

// Files worth opening. `cacerts` has no extension at all and is the one every
// JDK ships, so it is matched by name.
var keystoreExtensions = map[string]bool{
	".jks": true, ".jceks": true, ".keystore": true, ".truststore": true,
	".ks": true, ".p12": true, ".pfx": true,
}

func looksLikeKeystore(name string) bool {
	if strings.EqualFold(name, "cacerts") {
		return true
	}
	return keystoreExtensions[strings.ToLower(filepath.Ext(name))]
}

// Keystores finds the certificates inside Java keystores.
//
// These are invisible to every other collector. A .jks is neither PEM nor DER,
// so a filesystem walk reads straight past it — which means a Tomcat, a JBoss or
// an Elasticsearch terminating TLS on a host looks, to every other source, like
// a machine with no certificates on it at all.
//
// It never needs a password. Certificate entries in a JKS are not encrypted, so
// the certificates come out of a store whose password nobody has told the agent
// — which is the usual situation on a machine where the keystore was set up
// years ago by somebody who has left.
type Keystores struct {
	Bounds KeystoreBounds
}

func (c *Keystores) Source() string { return SourceJavaKeystore }

func (c *Keystores) Collect(ctx context.Context) Result {
	b := c.Bounds.withDefaults()
	res := Result{Source: SourceJavaKeystore, Completed: true}
	seen := 0
	// Paths already examined, so a file reached through two roots is reported
	// ONCE. The default roots deliberately overlap — `/opt/tomcat*/conf` and
	// `/opt/*/conf` both match /opt/tomcat/conf — because covering the layouts
	// people actually use means accepting overlap. What must not follow is
	// scanning the same keystore twice.
	examined := map[string]bool{}

	// JAVA_HOME is where a hand-installed JDK lives, and a hand-installed JDK
	// is exactly the one that is not in any of the standard directories.
	roots := b.Roots
	if home := os.Getenv("JAVA_HOME"); home != "" {
		roots = append(roots, filepath.Join(home, "lib", "security"),
			filepath.Join(home, "jre", "lib", "security"))
	}

	for _, root := range roots {
		if ctx.Err() != nil {
			res.Completed = false
			return res
		}
		matches, err := filepath.Glob(root)
		if err != nil || len(matches) == 0 {
			if _, statErr := os.Stat(root); statErr != nil {
				continue // Not on this host. Most of these will not be.
			}
			matches = []string{root}
		}
		for _, dir := range matches {
			if err := c.walk(ctx, dir, b, &res, &seen, examined); err != nil {
				res.Completed = false
				res.Errors = append(res.Errors, Error{
					Collector: SourceJavaKeystore, Location: dir, Error: err.Error(),
				})
			}
		}
	}
	return res
}

func (c *Keystores) walk(ctx context.Context, root string, b KeystoreBounds, res *Result, seen *int, examined map[string]bool) error {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			res.Completed = false
			res.Errors = append(res.Errors, Error{
				Collector: SourceJavaKeystore, Location: path, Error: err.Error(),
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
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !looksLikeKeystore(d.Name()) {
			return nil
		}
		if *seen >= b.MaxFiles {
			res.Completed = false
			return filepath.SkipAll
		}
		*seen++

		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > b.MaxFileBytes {
			return nil
		}
		c.examine(path, info, res, examined)
		return nil
	})
}

func (c *Keystores) examine(path string, info fs.FileInfo, res *Result, examined map[string]bool) {
	// Measured end to end against a live DTP: a Tomcat keystore under
	// /opt/tomcat/conf was reported TWICE, six observations for three aliases,
	// because two default roots glob to the same directory. The server's upsert
	// collapsed them so no data was wrong — but `dtp-agent scan` printed every
	// alias twice, and the run recorded 12 observations for 9 placements, which
	// is the number a member reads.
	resolved, err := filepath.Abs(path)
	if err != nil {
		resolved = path
	}
	if examined[resolved] {
		return
	}
	examined[resolved] = true

	data, err := os.ReadFile(path)
	if err != nil {
		res.Completed = false
		res.Errors = append(res.Errors, Error{
			Collector: SourceJavaKeystore, Location: path, Error: err.Error(),
		})
		return
	}

	entries, format, err := readKeystore(data)
	if errors.Is(err, parse.ErrNotAJavaKeystore) || errors.Is(err, parse.ErrNoCertificates) {
		// Something else that happens to be named .keystore, or a PKCS#12 the
		// agent cannot open without a password it will not guess at. Neither is
		// a fault, and neither is a keystore whose contents went unseen in a way
		// worth telling a member about.
		return
	}
	if err != nil {
		// A keystore that was PARTLY read. What came back before the fault is
		// real and is reported; the sweep is not complete, because the aliases
		// after it were never seen and must not be treated as removed.
		res.Completed = false
		res.Errors = append(res.Errors, Error{
			Collector: SourceJavaKeystore, Location: path, Error: err.Error(),
		})
	}

	for _, entry := range entries {
		leaf, chain, found := parse.Leaf(entry.Certificates)
		if !found {
			// An alias holding only CA certificates is a trust anchor, not a
			// deployment — and cacerts, which is on every host with a JDK, is
			// a hundred and fifty of them. Reporting those would bury the
			// certificates a member is paying to keep track of under the list
			// of issuers their JDK happens to ship with.
			//
			// A PrivateKeyEntry is different however its basicConstraints read:
			// the keystore holds the key, so this host can present it. A
			// self-signed certificate generated by keytool or openssl is very
			// often marked CA:TRUE, and skipping those would lose exactly the
			// internal services nobody else is watching.
			// AND ONLY IF THERE IS A CERTIFICATE TO REPORT. A key entry can
			// carry an empty chain — the format permits chainLen 0, and an
			// entry whose certificates all failed to parse arrives here
			// identically, because one unreadable certificate does not
			// invalidate the aliases around it. Indexing [0] there panics, and
			// Collect has no recover, so a single odd alias would abort the
			// entire scan of a host. There is nothing to inventory in a key
			// with no certificate, so this is silence rather than an error.
			if !entry.HasPrivateKey || len(entry.Certificates) == 0 {
				continue
			}
			leaf, chain = entry.Certificates[0], entry.Certificates[1:]
		}
		res.Observations = append(res.Observations, Observation{
			CertificatePEM: parse.EncodePEM([]*x509.Certificate{leaf}),
			ChainPEM:       parse.EncodePEM(chain),
			Source:         SourceJavaKeystore,
			// The alias, not just the file. It is what `keytool -delete -alias`
			// takes, and on a store with six aliases it is the only thing that
			// says which one is expiring.
			Location: path + ":" + entry.Alias,
			Binding: map[string]string{
				"keystore": path,
				"alias":    entry.Alias,
				"format":   format,
			},
			PrivateKeyPresent: entry.HasPrivateKey,
			// The key is INSIDE the keystore, so the keystore is where an
			// operator has to go — there is no separate file to point at.
			PrivateKeyLocation: keyLocation(path, entry.HasPrivateKey),
			FileMode:           fileMode(info),
			FileOwner:          fileOwner(info),
			ObservedAt:         time.Now().UTC(),
		})
	}
}

func keyLocation(path string, hasKey bool) string {
	if !hasKey {
		return ""
	}
	return path
}

// readKeystore tries the Sun formats first and PKCS#12 second, returning which
// one it turned out to be so the finding can say so.
func readKeystore(data []byte) ([]parse.KeystoreEntry, string, error) {
	entries, err := parse.JavaKeystore(data)
	if !errors.Is(err, parse.ErrNotAJavaKeystore) {
		return entries, keystoreFormat(data), err
	}

	// Since JDK 9 `keytool` writes PKCS#12 by default, so a file called
	// `.jks` is now as likely to be one of those as a real JKS.
	//
	// Only the empty password is tried. Guessing at passwords is not something
	// this agent does on a customer's machine, and a store it cannot open is
	// left unopened rather than attacked.
	result, p12Err := parse.PKCS12(data, "")
	if p12Err != nil {
		return nil, "", parse.ErrNotAJavaKeystore
	}
	return []parse.KeystoreEntry{{
		Alias:         "",
		Certificates:  result.Certificates,
		HasPrivateKey: result.HadPrivateKey,
	}}, "pkcs12", nil
}

func keystoreFormat(data []byte) string {
	if len(data) >= 4 && data[0] == 0xCE && data[1] == 0xCE && data[2] == 0xCE && data[3] == 0xCE {
		return "jceks"
	}
	return "jks"
}
