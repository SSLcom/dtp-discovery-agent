package collect

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// ServerConfigBounds keeps configuration parsing to something that terminates.
//
// A web server's configuration is a graph, not a tree: includes take globs,
// globs can match the directory they are written in, and a config that includes
// itself is a real thing people have on real machines. Every bound here exists
// because the alternative is an agent that never finishes.
type ServerConfigBounds struct {
	// NginxConfigs and ApacheConfigs are candidate MAIN configuration files.
	// One that is not on this host is not an error — most machines run one web
	// server or none.
	NginxConfigs  []string
	ApacheConfigs []string

	MaxFiles     int
	MaxFileBytes int64
	MaxDepth     int
}

func DefaultServerConfigBounds() ServerConfigBounds {
	b := ServerConfigBounds{
		NginxConfigs: []string{
			"/etc/nginx/nginx.conf",
			"/usr/local/nginx/conf/nginx.conf",
			"/usr/local/etc/nginx/nginx.conf",
			"/opt/homebrew/etc/nginx/nginx.conf",
		},
		ApacheConfigs: []string{
			"/etc/apache2/apache2.conf",
			"/etc/apache2/httpd.conf",
			"/etc/httpd/conf/httpd.conf",
			"/usr/local/etc/httpd/httpd.conf",
			"/opt/homebrew/etc/httpd/httpd.conf",
		},
		MaxFiles:     500,
		MaxFileBytes: 4 << 20,
		MaxDepth:     16,
	}
	if runtime.GOOS == "windows" {
		// IIS keeps its bindings in applicationHost.config, but the
		// certificates themselves live in the Windows certificate store and the
		// binding names only a thumbprint. Parsing it without a store collector
		// would yield sites with no certificate to report, so IIS waits for the
		// os_store collector rather than producing findings it cannot complete.
		b.NginxConfigs = []string{`C:\nginx\conf\nginx.conf`}
		b.ApacheConfigs = []string{`C:\Apache24\conf\httpd.conf`}
	}
	return b
}

func (b ServerConfigBounds) withDefaults() ServerConfigBounds {
	d := DefaultServerConfigBounds()
	if b.NginxConfigs == nil {
		b.NginxConfigs = d.NginxConfigs
	}
	if b.ApacheConfigs == nil {
		b.ApacheConfigs = d.ApacheConfigs
	}
	if b.MaxFiles <= 0 {
		b.MaxFiles = d.MaxFiles
	}
	if b.MaxFileBytes <= 0 {
		b.MaxFileBytes = d.MaxFileBytes
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = d.MaxDepth
	}
	return b
}

// ServerConfig finds certificates by reading what the web servers on this host
// were told to serve.
//
// It is the only source that knows WHICH SITE a certificate belongs to. The file
// collector can say a certificate is at /etc/ssl/site.pem; only the
// configuration says it is what www.example.com presents, that the key is the
// file two directories away, and that a second certificate is configured
// alongside it for clients that cannot do ECDSA. It also finds the certificates
// nothing else does: a path outside every scanned root is still found here,
// because the configuration named it.
type ServerConfig struct {
	Bounds ServerConfigBounds
}

func (c *ServerConfig) Source() string { return SourceServerConfig }

// vhost is one configured site and the certificates it was told to present.
type vhost struct {
	Server string // "nginx" or "apache", as it appears in the binding
	File   string // the configuration file the site was declared in
	Names  []string
	Listen []string
	Certs  []certificateRef
}

// certificateRef is a certificate as the configuration refers to it: by path,
// with the key and chain the configuration says go with it. THE KEY IS NEVER
// OPENED. Its path is recorded because an operator needs to know a key exists
// and what mode it is; its bytes are not this agent's business.
type certificateRef struct {
	Certificate string
	Key         string
	Chain       string
}

// primaryName is what identifies the site to a person.
func (v vhost) primaryName() string {
	for _, n := range v.Names {
		// A wildcard or catch-all is a poor label when a real name is present.
		if n != "" && n != "_" && !strings.HasPrefix(n, "*") {
			return n
		}
	}
	if len(v.Names) > 0 {
		return v.Names[0]
	}
	if len(v.Listen) > 0 {
		return v.Listen[0]
	}
	return "default"
}

// location identifies this site's placement, stably across runs.
//
// Keyed on the configuration FILE and the site's name rather than on the
// certificate path, because the placement being reported is the site: two sites
// sharing one certificate file are two placements, and collapsing them onto the
// path would lose one of them. Two certificates within ONE site do not collide
// either — the server's uniqueness runs over the certificate as well as the
// location, so a vhost configured with an RSA and an ECDSA certificate records
// both against the same site, which is exactly what it has.
func (v vhost) location() string {
	return v.File + ":" + v.primaryName()
}

func (c *ServerConfig) Collect(ctx context.Context) Result {
	b := c.Bounds.withDefaults()
	res := Result{Source: SourceServerConfig, Completed: true}

	readers := []struct {
		server  string
		configs []string
		parse   func(*configReader, string) ([]vhost, error)
	}{
		{"nginx", b.NginxConfigs, parseNginx},
		{"apache", b.ApacheConfigs, parseApache},
	}

	for _, r := range readers {
		for _, path := range r.configs {
			if ctx.Err() != nil {
				res.Completed = false
				return res
			}
			if _, err := os.Stat(path); err != nil {
				// This web server is not installed here, or not installed
				// there. Not a finding and not a fault.
				continue
			}

			reader := newConfigReader(b)
			hosts, err := r.parse(reader, path)
			if err != nil {
				res.Completed = false
				res.Errors = append(res.Errors, Error{
					Collector: SourceServerConfig, Location: path, Error: err.Error(),
				})
				continue
			}
			// A file the parser could not open or expand means sites it never
			// saw, so its silence cannot be used to retire anything.
			for _, problem := range reader.problems {
				res.Completed = false
				res.Errors = append(res.Errors, problem)
			}
			for _, host := range hosts {
				c.record(host, &res)
			}
		}
	}

	// IIS, which is read differently from the others because it IS different:
	// a site's certificate is not in its configuration file but in HTTP.sys and
	// the certificate store, so there is no path to open and parse.
	observations, problems, complete := iisObservations()
	res.Observations = append(res.Observations, observations...)
	res.Errors = append(res.Errors, problems...)
	if !complete {
		res.Completed = false
	}
	return res
}

// record turns one configured site into observations, reading each certificate
// the configuration pointed at.
func (c *ServerConfig) record(host vhost, res *Result) {
	for _, ref := range host.Certs {
		data, err := os.ReadFile(ref.Certificate)
		if err != nil {
			// THE CONFIGURATION SAYS A CERTIFICATE IS HERE AND IT IS NOT. That
			// is a finding, not a collector failing: the site is broken, or
			// will be the next time the server reloads.
			//
			// WHETHER IT SPOILS THE SWEEP TURNS ENTIRELY ON WHY, and an earlier
			// draft got this backwards by treating every read failure the same.
			// A file that is GONE is something the collector saw clearly, and
			// the placement it used to hold genuinely should be retired —
			// marking the sweep incomplete would PREVENT that and leave the
			// portfolio insisting a deleted certificate is still deployed.
			// Anything else (a permission error, an NFS mount that went away) is
			// a certificate the agent could not see, which must not be read as
			// one that was removed.
			if !os.IsNotExist(err) {
				res.Completed = false
			}
			res.Errors = append(res.Errors, Error{
				Collector: SourceServerConfig,
				Location:  host.location(),
				Error:     fmt.Sprintf("%s is configured to serve %s, which could not be read: %v", host.Server, ref.Certificate, err),
			})
			continue
		}

		parsed, err := parse.Certificates(data)
		if err != nil || len(parsed.Certificates) == 0 {
			// The file is there and holds no certificate. Definite, seen, and
			// wrong — but not something the collector missed, so the sweep
			// stands and the placement can be retired.
			res.Errors = append(res.Errors, Error{
				Collector: SourceServerConfig,
				Location:  host.location(),
				Error:     fmt.Sprintf("%s is configured to serve %s, which holds no certificate", host.Server, ref.Certificate),
			})
			continue
		}

		// A configured certificate is reported WHATEVER it holds. Unlike a file
		// the agent merely came across, this one is what the site presents — so
		// if someone has pointed ssl_certificate at a chain file, that is a
		// finding rather than something to skip. The leaf is still preferred
		// where there is one, because bundles are not reliably ordered.
		leaf, chain, found := parse.Leaf(parsed.Certificates)
		if !found {
			leaf, chain = parsed.Certificates[0], parsed.Certificates[1:]
		}
		// Apache before 2.4.8 kept the intermediates in a separate file. Read
		// it if the configuration named one: a chain the agent can see is a
		// chain DTP can check, and a missing intermediate is its own outage.
		if ref.Chain != "" {
			if extra, err := os.ReadFile(ref.Chain); err == nil {
				if chainCerts, err := parse.Certificates(extra); err == nil {
					chain = append(chain, chainCerts.Certificates...)
				}
			}
		}

		binding := map[string]string{
			"server":           host.Server,
			"config_file":      host.File,
			"certificate_file": ref.Certificate,
		}
		if len(host.Names) > 0 {
			binding["server_name"] = host.Names[0]
			if len(host.Names) > 1 {
				binding["server_names"] = strings.Join(host.Names, " ")
			}
		}
		if len(host.Listen) > 0 {
			binding["listen"] = strings.Join(host.Listen, " ")
		}

		res.Observations = append(res.Observations, Observation{
			CertificatePEM: parse.EncodePEM([]*x509.Certificate{leaf}),
			ChainPEM:       parse.EncodePEM(chain),
			Source:         SourceServerConfig,
			Location:       host.location(),
			Binding:        binding,
			// The configuration TELLS us where the key is. That is better than
			// the file collector's guess from a matching filename, and it is
			// why this is worth recording here as well: a key nobody would have
			// looked for is still a key sitting at mode 0644.
			PrivateKeyPresent:  ref.Key != "" || parsed.HadPrivateKey,
			PrivateKeyLocation: ref.Key,
			FileMode:           fileModeOf(ref.Certificate),
			FileOwner:          fileOwnerOf(ref.Certificate),
			ObservedAt:         time.Now().UTC(),
		})
	}
}

// ServerNamesFrom is every name the configured sites answer to, which is what
// the listener probe sends as SNI. Without it a name-based virtual host answers
// the probe with its DEFAULT certificate and the other twenty sites on the
// machine are invisible.
func ServerNamesFrom(results []Result) []string {
	seen := map[string]bool{}
	var names []string
	for _, r := range results {
		if r.Source != SourceServerConfig {
			continue
		}
		for _, o := range r.Observations {
			for _, name := range strings.Fields(o.Binding["server_names"]) {
				addServerName(name, seen, &names)
			}
			addServerName(o.Binding["server_name"], seen, &names)
		}
	}
	sort.Strings(names)
	return names
}

func addServerName(name string, seen map[string]bool, out *[]string) {
	// A wildcard, a regular expression (nginx allows `~^...$`) or a catch-all
	// is not a name SNI can carry. Sending one asks the server a question no
	// client would ask, and the answer would be filed against a site that does
	// not exist.
	if name == "" || name == "_" || seen[name] ||
		strings.ContainsAny(name, "*~^$ ") {
		return
	}
	seen[name] = true
	*out = append(*out, name)
}

// ── shared include machinery ─────────────────────────────────────────────────

// configReader opens the files a configuration refers to, once each.
//
// The "once each" is not an optimisation. An include glob that matches the
// directory it lives in is a cycle, and a configuration that includes itself is
// something people genuinely have; without this the agent parses until it runs
// out of stack on a machine nobody is watching.
type configReader struct {
	bounds   ServerConfigBounds
	visited  map[string]bool
	opened   int
	problems []Error
}

func newConfigReader(b ServerConfigBounds) *configReader {
	return &configReader{bounds: b, visited: map[string]bool{}}
}

func (r *configReader) note(path string, err error) {
	r.problems = append(r.problems, Error{
		Collector: SourceServerConfig, Location: path, Error: err.Error(),
	})
}

// read returns a configuration file's contents, or nil if it has been seen, is
// too large, or could not be opened. Every refusal after the first is recorded,
// because a file the parser skipped holds sites it never saw.
func (r *configReader) read(path string) []byte {
	resolved, err := filepath.Abs(path)
	if err != nil {
		resolved = path
	}
	if r.visited[resolved] {
		return nil
	}
	r.visited[resolved] = true

	if r.opened >= r.bounds.MaxFiles {
		r.note(path, fmt.Errorf("stopped after %d configuration files", r.bounds.MaxFiles))
		return nil
	}
	info, err := os.Stat(resolved)
	if err != nil {
		r.note(path, err)
		return nil
	}
	if info.IsDir() {
		return nil // An include glob that matched a directory.
	}
	if info.Size() > r.bounds.MaxFileBytes {
		r.note(path, fmt.Errorf("configuration file is %d bytes, over the %d-byte limit", info.Size(), r.bounds.MaxFileBytes))
		return nil
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		r.note(path, err)
		return nil
	}
	r.opened++
	return data
}

// expand resolves an include pattern to the files it names, relative to the
// including file's directory when it is not absolute — which is how both nginx
// and Apache read them.
func (r *configReader) expand(pattern, relativeTo string) []string {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(relativeTo, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		r.note(pattern, err)
		return nil
	}
	if matches == nil {
		// An include that matches nothing is normal — sites-enabled is empty on
		// a fresh install — and only worth reporting when the pattern is a
		// plain path, where it means a file the server itself will fail on.
		if !strings.ContainsAny(pattern, "*?[") {
			r.note(pattern, os.ErrNotExist)
		}
		return nil
	}
	sort.Strings(matches)
	return matches
}

func fileModeOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fileMode(info)
}

func fileOwnerOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fileOwner(info)
}
