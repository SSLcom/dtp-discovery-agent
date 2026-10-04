package collect

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two collectors have an ordering dependency and it is invisible from
// either one of them: the configuration knows the names a name-based virtual
// host answers to, and the probe cannot see past the default certificate
// without them. Run them the other way round and the machines with the MOST
// sites report the fewest — with nothing about the output looking wrong.
//
// So this asserts the outcome rather than the order: a second site, reachable
// only by SNI, has to appear.
func TestTheProbeIsToldTheNamesTheConfigurationFound(t *testing.T) {
	fallback := selfSigned(t, "default.example.com")
	alpha := selfSigned(t, "alpha.example.com")

	port := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{fallback},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "alpha.example.com" {
				return &alpha, nil
			}
			return &fallback, nil
		},
	})

	root := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        listen 443 ssl;
        server_name alpha.example.com;
        ssl_certificate {{root}}/ssl/alpha.pem;
    }
}
`,
	})
	writeLeaf(t, filepath.Join(root, "ssl/alpha.pem"), "alpha.example.com")

	results := Run(context.Background(), Options{
		// Nothing to find on disk; this test is about the other two.
		File: Bounds{Roots: []string{t.TempDir()}},
		ServerConfig: ServerConfigBounds{
			NginxConfigs:  []string{filepath.Join(root, "nginx.conf")},
			ApacheConfigs: []string{},
		},
		Listener: ListenerBounds{Ports: []int{port}, Timeout: 3 * time.Second},
	})

	var served []string
	for _, r := range results {
		if r.Source != SourceListener {
			continue
		}
		served = append(served, commonNames(t, r)...)
	}

	if strings.Join(served, ",") != "default.example.com,alpha.example.com" {
		t.Fatalf("the probe served %v; without the configured name it can only ever see the default", served)
	}
}

func TestADisabledSourceDoesNotRun(t *testing.T) {
	results := Run(context.Background(), Options{
		File:         Bounds{Roots: []string{t.TempDir()}},
		ServerConfig: ServerConfigBounds{NginxConfigs: []string{}, ApacheConfigs: []string{}},
		Listener:     ListenerBounds{Ports: []int{1}, Timeout: time.Second},
		Disabled:     []string{SourceListener, SourceServerConfig},
	})

	for _, r := range results {
		if r.Source == SourceListener || r.Source == SourceServerConfig {
			t.Errorf("%s ran although it was disabled", r.Source)
		}
	}
	// Derived from the collector list rather than written as a number, so
	// adding a collector does not quietly turn this into an assertion about
	// something else.
	if want := len(Names()) - 2; len(results) != want {
		t.Fatalf("got %d results, want the %d sources that were not disabled", len(results), want)
	}
	// A disabled source is never DECLARED complete either, which is what makes
	// turning one off leave its past findings stale rather than retiring them.
	for _, r := range results {
		if r.Source == SourceListener && r.Completed {
			t.Error("a source that did not run cannot have swept anything")
		}
	}
}

// Every source this build collects has a collector behind it, and every
// collector's source is one DTP understands. A name that is neither is filed as
// "other" by the server, which quietly removes it from absence handling.
func TestEverySourceThisBuildReportsIsOneDTPKnows(t *testing.T) {
	known := map[string]bool{
		SourceFile: true, SourceOSStore: true, SourceJavaKeystore: true,
		SourceNSS: true, SourceListener: true, SourceServerConfig: true,
	}
	for _, name := range Names() {
		if !known[name] {
			t.Errorf("collector source %q is not one the platform understands", name)
		}
	}
	if len(Names()) == 0 {
		t.Fatal("a build with no collectors would scan nothing and report a clean sweep")
	}
}

func TestAMisspeltSourceIsRefusedRatherThanIgnored(t *testing.T) {
	if err := ValidateDisabled([]string{"listner"}); err == nil {
		t.Fatal("a typo must not silently leave the source running")
	}
	if err := ValidateDisabled(Names()); err != nil {
		t.Fatalf("every real source must be nameable: %v", err)
	}
}

// One file can be hundreds of observations, so a run has a limit across every
// source. Reaching it stops the run collecting, and it is not silent: the
// source it happened in, and every source after it, is incomplete — so the
// server marks nothing they missed as gone — and each says why.
func TestARunStopsAtItsLimitAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeLeaf(t, filepath.Join(dir, fmt.Sprintf("site%d.pem", i)), fmt.Sprintf("site%d.example.com", i))
	}
	opts := Options{
		File:      Bounds{Roots: []string{dir}},
		Keystores: KeystoreBounds{Roots: []string{t.TempDir()}},
		Disabled:  []string{SourceOSStore, SourceServerConfig, SourceListener},
	}

	for _, tc := range []struct {
		name  string
		limit *runCap
	}{
		{"by count", &runCap{maxCount: 3, maxBytes: MaxObservationBytesPerRun}},
		// writeLeaf's certificates are a few hundred bytes of PEM each.
		{"by size", &runCap{maxCount: MaxObservationsPerRun, maxBytes: 1500}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := runWithin(context.Background(), opts, tc.limit)
			if len(results) != 2 {
				t.Fatalf("got %d results, want file and java_keystore", len(results))
			}
			files, keystores := results[0], results[1]

			if n := len(files.Observations); n == 0 || n >= 5 {
				t.Errorf("file reported %d of 5; want the run to stop part-way", n)
			}
			if files.Completed || len(files.Errors) != 1 || !strings.Contains(files.Errors[0].Error, "was not reported") {
				t.Errorf("file: completed %v, errors %+v; want incomplete, with one error saying so", files.Completed, files.Errors)
			}
			if keystores.Completed || len(keystores.Errors) != 1 || !strings.Contains(keystores.Errors[0].Error, "was not run") {
				t.Errorf("java_keystore: completed %v, errors %+v; want not run, and saying so", keystores.Completed, keystores.Errors)
			}
		})
	}
}

// The real limit, untouched by a host with an ordinary number of certificates.
func TestAnOrdinaryRunIsNotLimited(t *testing.T) {
	dir := t.TempDir()
	writeLeaf(t, filepath.Join(dir, "site.pem"), "www.example.com")
	results := Run(context.Background(), Options{
		File:     Bounds{Roots: []string{dir}},
		Disabled: []string{SourceJavaKeystore, SourceOSStore, SourceServerConfig, SourceListener},
	})
	if len(results) != 1 || !results[0].Completed || len(results[0].Errors) != 0 || len(results[0].Observations) != 1 {
		t.Errorf("results %+v", results)
	}
}
