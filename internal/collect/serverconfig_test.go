package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func timeoutAfter() <-chan time.Time { return time.After(20 * time.Second) }

// tree writes a directory of files from relative path to contents, and returns
// the root. Certificate paths inside the configurations are written as
// {{root}}, which is substituted, so a fixture reads like the real file.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(body, "{{root}}", root)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func collectNginx(t *testing.T, root, main string) Result {
	t.Helper()
	c := &ServerConfig{Bounds: ServerConfigBounds{
		NginxConfigs:  []string{filepath.Join(root, main)},
		ApacheConfigs: []string{},
	}}
	return c.Collect(context.Background())
}

func collectApache(t *testing.T, root, main string) Result {
	t.Helper()
	c := &ServerConfig{Bounds: ServerConfigBounds{
		NginxConfigs:  []string{},
		ApacheConfigs: []string{filepath.Join(root, main)},
	}}
	return c.Collect(context.Background())
}

func onlyObservation(t *testing.T, res Result) Observation {
	t.Helper()
	if len(res.Observations) != 1 {
		t.Fatalf("expected one observation, got %d (errors: %v)", len(res.Observations), res.Errors)
	}
	return res.Observations[0]
}

// ── nginx ────────────────────────────────────────────────────────────────────

// The Debian layout, which is most of the nginx in the world: a main config
// that includes sites-enabled and nothing else of interest. An agent that
// treated includes as opaque would find no sites at all on these machines.
func TestNginxFindsASiteThroughSitesEnabled(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
user www-data;
http {
    # The certificates are per-site, in the files below.
    include {{root}}/sites-enabled/*.conf;
}
`,
		"sites-enabled/example.conf": `
server {
    listen 443 ssl http2;
    server_name www.example.com example.com;

    ssl_certificate     {{root}}/ssl/example.pem;
    ssl_certificate_key {{root}}/ssl/example.key;
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/example.pem"), "www.example.com")
	writeKey(t, filepath.Join(root, "ssl/example.key"))

	res := collectNginx(t, root, "nginx.conf")
	if !res.Completed {
		t.Errorf("a configuration that parsed cleanly is a complete sweep: %v", res.Errors)
	}

	obs := onlyObservation(t, res)
	if obs.Source != SourceServerConfig {
		t.Errorf("source = %q", obs.Source)
	}
	if want := filepath.Join(root, "sites-enabled/example.conf") + ":www.example.com"; obs.Location != want {
		t.Errorf("location = %q, want %q", obs.Location, want)
	}
	if obs.Binding["server"] != "nginx" {
		t.Errorf("binding lost which server this was: %v", obs.Binding)
	}
	if obs.Binding["server_names"] != "www.example.com example.com" {
		t.Errorf("every name the site answers to is worth recording: %v", obs.Binding)
	}
	if !strings.Contains(obs.Binding["listen"], "443") {
		t.Errorf("listen = %q", obs.Binding["listen"])
	}
	// The configuration NAMES the key. That is better than the file collector's
	// guess from a matching filename, and it is most of why this source exists.
	if obs.PrivateKeyLocation != filepath.Join(root, "ssl/example.key") {
		t.Errorf("private key location = %q", obs.PrivateKeyLocation)
	}
	if !obs.PrivateKeyPresent {
		t.Error("a configured key is a key that is present")
	}
}

// A certificate at http level is served by every site under it. A collector
// that only looked inside server blocks would call this host bare — and this is
// how a single-site machine is very often written.
func TestNginxInheritsACertificateFromTheHttpBlock(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    ssl_certificate     {{root}}/ssl/shared.pem;
    ssl_certificate_key {{root}}/ssl/shared.key;

    server {
        listen 443 ssl;
        server_name only.example.com;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/shared.pem"), "only.example.com")
	writeKey(t, filepath.Join(root, "ssl/shared.key"))

	obs := onlyObservation(t, collectNginx(t, root, "nginx.conf"))
	if obs.Binding["certificate_file"] != filepath.Join(root, "ssl/shared.pem") {
		t.Errorf("the inherited certificate was not found: %v", obs.Binding)
	}
}

// A site's own certificate replaces what it would have inherited, rather than
// adding to it. Reporting both would tell an operator a site serves a
// certificate it does not.
func TestNginxPrefersASitesOwnCertificateOverTheInheritedOne(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    ssl_certificate     {{root}}/ssl/shared.pem;
    ssl_certificate_key {{root}}/ssl/shared.key;

    server {
        server_name own.example.com;
        ssl_certificate     {{root}}/ssl/own.pem;
        ssl_certificate_key {{root}}/ssl/own.key;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/shared.pem"), "shared.example.com")
	writeLeaf(t, filepath.Join(root, "ssl/own.pem"), "own.example.com")
	writeKey(t, filepath.Join(root, "ssl/own.key"))

	obs := onlyObservation(t, collectNginx(t, root, "nginx.conf"))
	if obs.Binding["certificate_file"] != filepath.Join(root, "ssl/own.pem") {
		t.Errorf("the site's own certificate should win: %v", obs.Binding)
	}
}

// Both servers read several certificates POSITIONALLY, which is how one site
// presents RSA to an old client and ECDSA to everything else. Pairing by
// proximity, or taking only the first key, attaches the wrong key path to a
// certificate — and the key path is the whole reason an operator opens this.
func TestDualCertificateSitesPairEachKeyWithItsOwnCertificate(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name dual.example.com;
        ssl_certificate     {{root}}/ssl/rsa.pem;
        ssl_certificate_key {{root}}/ssl/rsa.key;
        ssl_certificate     {{root}}/ssl/ecdsa.pem;
        ssl_certificate_key {{root}}/ssl/ecdsa.key;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/rsa.pem"), "rsa.example.com")
	writeLeaf(t, filepath.Join(root, "ssl/ecdsa.pem"), "ecdsa.example.com")
	writeKey(t, filepath.Join(root, "ssl/rsa.key"))
	writeKey(t, filepath.Join(root, "ssl/ecdsa.key"))

	res := collectNginx(t, root, "nginx.conf")
	if len(res.Observations) != 2 {
		t.Fatalf("expected both certificates, got %d (%v)", len(res.Observations), res.Errors)
	}
	for _, obs := range res.Observations {
		cert := obs.Binding["certificate_file"]
		wantKey := strings.TrimSuffix(cert, ".pem") + ".key"
		if obs.PrivateKeyLocation != wantKey {
			t.Errorf("%s was paired with %s, want %s", cert, obs.PrivateKeyLocation, wantKey)
		}
	}
	// Both are the same site, so both are recorded against it. The server's
	// uniqueness runs over the certificate too, so they do not collide.
	if res.Observations[0].Location != res.Observations[1].Location {
		t.Errorf("one site should be one location: %q and %q",
			res.Observations[0].Location, res.Observations[1].Location)
	}
}

// An include glob that matches the directory it is written in is a cycle, and a
// configuration that includes itself is something real machines have. Without
// the visited set this runs until the agent dies, on a machine nobody is
// watching.
func TestAnIncludeCycleTerminates(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    include {{root}}/other.conf;
    server { server_name looped.example.com; ssl_certificate {{root}}/ssl/x.pem; }
}
`,
		"other.conf": `include {{root}}/nginx.conf;
include {{root}}/other.conf;
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/x.pem"), "looped.example.com")

	done := make(chan Result, 1)
	go func() { done <- collectNginx(t, root, "nginx.conf") }()

	select {
	case res := <-done:
		if len(res.Observations) != 1 {
			t.Errorf("expected the one real site, got %d", len(res.Observations))
		}
	case <-timeoutAfter():
		t.Fatal("parsing did not terminate on a self-including configuration")
	}
}

func TestNginxIgnoresCommentsAndKeepsQuotedPaths(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name quoted.example.com;   # the site, not a # comment marker
        # ssl_certificate {{root}}/ssl/commented-out.pem;
        ssl_certificate "{{root}}/ssl/a path/site.pem";
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/a path/site.pem"), "quoted.example.com")
	writeLeaf(t, filepath.Join(root, "ssl/commented-out.pem"), "commented.example.com")

	obs := onlyObservation(t, collectNginx(t, root, "nginx.conf"))
	if !strings.Contains(obs.Binding["certificate_file"], "a path") {
		t.Errorf("a quoted path with a space was split: %v", obs.Binding)
	}
}

// nginx allows a certificate that is not a file at all: a variable, an inline
// data: blob, a PKCS#11 URI. The server does not open those as files and
// neither should the agent — reporting one as a missing certificate raises an
// alarm about a site that is working perfectly.
func TestACertificateThatIsNotAFileIsNotReportedMissing(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name dynamic.example.com;
        ssl_certificate $ssl_server_name.pem;
    }
    server {
        server_name pkcs11.example.com;
        ssl_certificate "engine:pkcs11:object=cert";
    }
}
`,
	})

	res := collectNginx(t, root, "nginx.conf")
	if len(res.Errors) != 0 {
		t.Errorf("a certificate nginx would not open as a file is not a missing file: %v", res.Errors)
	}
	if !res.Completed {
		t.Error("nothing here should spoil the sweep")
	}
}

// ── apache ───────────────────────────────────────────────────────────────────

func TestApacheFindsASiteThroughSitesEnabled(t *testing.T) {
	root := tree(t, map[string]string{
		"apache2.conf": `
# Debian's layout: ServerRoot is this directory, and the sites are elsewhere.
IncludeOptional sites-enabled/*.conf
`,
		"sites-enabled/example.conf": `
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName  https://www.example.com:443
    ServerAlias example.com  static.example.com

    SSLEngine on
    SSLCertificateFile    {{root}}/ssl/example.pem
    SSLCertificateKeyFile {{root}}/ssl/example.key
</VirtualHost>
</IfModule>
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/example.pem"), "www.example.com")
	writeKey(t, filepath.Join(root, "ssl/example.key"))

	res := collectApache(t, root, "apache2.conf")
	if !res.Completed {
		t.Errorf("clean parse, complete sweep: %v", res.Errors)
	}
	obs := onlyObservation(t, res)

	// A VirtualHost inside <IfModule> is the ordinary way to write a
	// conditional site; treating the wrapper as opaque loses it.
	if obs.Binding["server"] != "apache" {
		t.Errorf("binding = %v", obs.Binding)
	}
	// ServerName may carry a scheme and a port. Neither belongs in a name, and
	// an SNI probe sent "https://www.example.com:443" asks a question no client
	// would ask.
	if obs.Binding["server_name"] != "www.example.com" {
		t.Errorf("server_name = %q, want the bare name", obs.Binding["server_name"])
	}
	if want := "www.example.com example.com static.example.com"; obs.Binding["server_names"] != want {
		t.Errorf("server_names = %q, want %q", obs.Binding["server_names"], want)
	}
	if obs.PrivateKeyLocation != filepath.Join(root, "ssl/example.key") {
		t.Errorf("private key location = %q", obs.PrivateKeyLocation)
	}
}

// Red Hat puts httpd.conf in conf/ under a ServerRoot of /etc/httpd, so
// `IncludeOptional conf.d/*.conf` means /etc/httpd/conf.d — NOT the including
// file's own directory. Resolving includes the wrong way finds every site on
// Debian and none on Red Hat, which is the kind of gap that looks like "the
// agent works" right up until half an estate reports nothing.
func TestApacheResolvesIncludesAgainstServerRootNotTheIncludingFile(t *testing.T) {
	root := tree(t, map[string]string{
		"conf/httpd.conf": `
ServerRoot "{{root}}"
IncludeOptional conf.d/*.conf
`,
		"conf.d/ssl.conf": `
<VirtualHost _default_:443>
    ServerName rhel.example.com
    SSLCertificateFile    {{root}}/ssl/rhel.pem
    SSLCertificateKeyFile {{root}}/ssl/rhel.key
</VirtualHost>
`,
		// The trap: a same-named directory under the including file's own
		// directory. Resolving relative to the file finds THIS one instead, and
		// every assertion about "a site was found" would still pass.
		"conf/conf.d/decoy.conf": `
<VirtualHost *:443>
    ServerName decoy.example.com
    SSLCertificateFile {{root}}/ssl/decoy.pem
</VirtualHost>
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/rhel.pem"), "rhel.example.com")
	writeLeaf(t, filepath.Join(root, "ssl/decoy.pem"), "decoy.example.com")
	writeKey(t, filepath.Join(root, "ssl/rhel.key"))

	obs := onlyObservation(t, collectApache(t, root, "conf/httpd.conf"))
	if obs.Binding["server_name"] != "rhel.example.com" {
		t.Fatalf("includes resolved against the wrong root: found %q", obs.Binding["server_name"])
	}
}

func TestApacheJoinsContinuedLines(t *testing.T) {
	root := tree(t, map[string]string{
		"httpd.conf": `
<VirtualHost *:443>
    ServerName continued.example.com
    SSLCertificateFile \
        {{root}}/ssl/continued.pem
</VirtualHost>
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/continued.pem"), "continued.example.com")

	obs := onlyObservation(t, collectApache(t, root, "httpd.conf"))
	if obs.Binding["certificate_file"] != filepath.Join(root, "ssl/continued.pem") {
		t.Errorf("a continued directive was not joined: %v", obs.Binding)
	}
}

// ── findings that are not certificates ───────────────────────────────────────

// The configuration says a certificate is at a path and it is not there. That
// is not the collector failing to find something — it is the finding. The site
// is broken, or will be the next time the server reloads.
func TestAConfiguredCertificateThatIsMissingIsReported(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name gone.example.com;
        ssl_certificate {{root}}/ssl/never-written.pem;
    }
}
`,
	})

	res := collectNginx(t, root, "nginx.conf")
	if len(res.Errors) != 1 {
		t.Fatalf("expected the missing certificate to be reported, got %v", res.Errors)
	}
	if !strings.Contains(res.Errors[0].Error, "never-written.pem") {
		t.Errorf("the error should name the file: %q", res.Errors[0].Error)
	}
	// A file that is GONE was seen clearly, and the placement it used to hold
	// should be retired. Marking the sweep incomplete would prevent exactly
	// that, and leave the portfolio insisting a deleted certificate is still
	// deployed on a host where it plainly is not.
	if !res.Completed {
		t.Error("a certificate that is definitely gone must not stop the sweep retiring it")
	}
}

// The other half: a certificate the agent could not READ is not one that was
// removed. A permission error, or an NFS mount that went away, must not let DTP
// tell an operator a certificate disappeared from a host where it is sitting
// exactly where it always was.
func TestAConfiguredCertificateThatCannotBeReadStopsTheSweep(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so this cannot be shown here")
	}
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name locked.example.com;
        ssl_certificate {{root}}/ssl/locked.pem;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/locked.pem"), "locked.example.com")
	if err := os.Chmod(filepath.Join(root, "ssl/locked.pem"), 0o000); err != nil {
		t.Fatal(err)
	}

	res := collectNginx(t, root, "nginx.conf")
	if len(res.Errors) != 1 {
		t.Fatalf("expected the unreadable certificate to be reported, got %v", res.Errors)
	}
	if res.Completed {
		t.Error("a certificate the agent could not see must not be reported as one that was removed")
	}
}

// Most machines run one web server or none. An absent configuration is not a
// finding and not a fault, and an agent that reported it would put an error on
// every host in an estate.
func TestNoWebServerInstalledIsSilentAndComplete(t *testing.T) {
	c := &ServerConfig{Bounds: ServerConfigBounds{
		NginxConfigs:  []string{filepath.Join(t.TempDir(), "nginx.conf")},
		ApacheConfigs: []string{filepath.Join(t.TempDir(), "httpd.conf")},
	}}
	res := c.Collect(context.Background())

	if len(res.Observations) != 0 || len(res.Errors) != 0 {
		t.Errorf("a host with no web server produced %v / %v", res.Observations, res.Errors)
	}
	if !res.Completed {
		t.Error("nothing to read is not the same as failing to read")
	}
}

// ── feeding the listener probe ───────────────────────────────────────────────

func TestServerNamesFeedTheListenerProbe(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        server_name www.example.com example.com *.wild.example.com _ ~^app\d+\.example\.com$;
        ssl_certificate {{root}}/ssl/x.pem;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/x.pem"), "www.example.com")

	names := ServerNamesFrom([]Result{collectNginx(t, root, "nginx.conf")})

	want := []string{"example.com", "www.example.com"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		// A wildcard, a regular expression and the catch-all `_` are not names
		// SNI can carry. Sending one asks a question no client would ask, and
		// the answer gets filed against a site that does not exist.
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestServerNamesIgnoreOtherSources(t *testing.T) {
	names := ServerNamesFrom([]Result{{
		Source:       SourceFile,
		Observations: []Observation{{Binding: map[string]string{"server_name": "not.a.site"}}},
	}})
	if len(names) != 0 {
		t.Errorf("only the configuration knows a site's names, got %v", names)
	}
}
