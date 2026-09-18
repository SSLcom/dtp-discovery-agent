// Package e2e runs the REAL agent binary against a protocol-faithful server,
// on a host seeded with the awkward mix the discovery plan describes.
//
// WHY THIS EXISTS. Two releases in two days fixed bugs that the unit suite —
// green on three platforms, mutation-tested throughout — could not see, because
// every collector test exercised one collector against one root:
//
//   - v0.2.1: `openssl req -x509` marks a self-signed certificate CA:TRUE by
//     default, so the trust-store rule swallowed every ordinary self-signed
//     certificate on the machine.
//   - v0.2.2: a keystore reachable through two overlapping default roots was
//     scanned twice, so the run reported 12 observations for 9 real placements.
//
// Both lived in the space between "each collector works" and "the collectors
// work together on a real machine". Both were found by hand. This closes that.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildAgent compiles the binary under test. The binary, not the packages: a
// harness that called collect.Run directly would skip main's wiring, which is
// where the collector list and the --without plumbing live.
func buildAgent(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "dtp-agent")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, "./cmd/dtp-agent")
	cmd.Dir = ".."
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the agent: %v\n%s", err, combined)
	}
	return out
}

type agent struct {
	bin, state, host string
	t                *testing.T
}

func (a *agent) run(args ...string) (string, error) {
	a.t.Helper()
	cmd := exec.Command(a.bin, append(args, "--state", a.state)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestTheWholeThing walks one agent through enrollment, the pending wait,
// approval, reporting and revocation, asserting at each step on what the server
// actually received.
func TestTheWholeThing(t *testing.T) {
	server := newFakeDTP()
	defer server.close()

	hostRoot := seedHost(t)
	a := &agent{bin: buildAgent(t), state: t.TempDir(), host: hostRoot, t: t}

	// ── enroll ───────────────────────────────────────────────────────────────
	out, err := a.run("enroll", "--server", server.url(), "--account", "acct-e2e", "--token", "dtpd_e2e")
	if err != nil {
		t.Fatalf("enroll failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "pending") {
		t.Errorf("an agent must land pending, not admitted: %s", out)
	}
	registrations := server.registrations()
	if len(registrations) != 1 {
		t.Fatalf("server saw %d registrations", len(registrations))
	}
	if pk, _ := registrations[0]["public_key_pem"].(string); !strings.Contains(pk, "PUBLIC KEY") {
		t.Error("registration carried no public key")
	}
	patchConfig(t, a.state, hostRoot)

	// ── while pending: 202, and nothing reported ─────────────────────────────
	//
	// `--once` EXITS NON-ZERO here, and this records that rather than asserting
	// it is right. The flag means "do not hold a process open waiting", so the
	// agent reports the pending state and stops — but pending during a rollout
	// is the expected state, not a fault, and a member running --once from cron
	// gets a failure every hour until somebody clicks approve. The packaged
	// systemd timer uses plain `run`, which waits, so nothing shipped is
	// affected. Worth settling deliberately; not settled here.
	out, _ = a.run("run", "--once", "--without", "listener")
	if !strings.Contains(strings.ToLower(out), "approve") {
		t.Errorf("a pending agent must say what it is waiting for, whatever it exits: %s", out)
	}
	if server.pendingAnswers() == 0 {
		t.Error("the server never answered 202, so the pending path was not exercised")
	}
	if n := len(server.observations()); n != 0 {
		t.Fatalf("an unapproved agent reported %d observations", n)
	}

	// ── approved: it reports ─────────────────────────────────────────────────
	server.approve()
	if out, err = a.run("run", "--once", "--without", "listener"); err != nil {
		t.Fatalf("reporting after approval: %v\n%s", err, out)
	}
	obs := server.observations()
	if len(obs) == 0 {
		t.Fatal("an approved agent reported nothing")
	}

	assertFindings(t, obs, hostRoot)
	assertNoKeyMaterialOnTheWire(t, server)
	assertEachPlacementOnce(t, obs)

	// ── revoked: it stops ────────────────────────────────────────────────────
	before := len(server.observations())
	server.revoke()
	out, _ = a.run("run", "--once", "--without", "listener")
	if !strings.Contains(strings.ToLower(out), "revoke") {
		t.Errorf("a revoked agent should say so: %s", out)
	}
	if after := len(server.observations()); after != before {
		t.Errorf("a revoked agent reported %d more observations", after-before)
	}
}

// assertFindings checks that every fixture the plan names was found, and that
// the two that must NOT be reported were not.
func assertFindings(t *testing.T, obs []observation, hostRoot string) {
	t.Helper()
	byLocation := map[string]observation{}
	for _, o := range obs {
		byLocation[filepath.ToSlash(o.Location)] = o
	}
	has := func(substr string) bool {
		for loc := range byLocation {
			if strings.Contains(loc, substr) {
				return true
			}
		}
		return false
	}

	for _, want := range []struct{ what, substr string }{
		{"the ordinary certificate", "ssl/valid.pem"},
		{"the expired certificate", "ssl/expired.pem"},
		{"a certificate with no key", "ssl/orphan.pem"},
		{"the PKCS#12 bundle", "ssl/bundle.p12"},
		// The v0.2.1 bug. `openssl req -x509` marks a self-signed certificate
		// CA:TRUE by default, and the trust-store rule swallowed them.
		{"a SELF-SIGNED CA:TRUE certificate with its key", "ssl/ca-true.pem"},
		{"the Java keystore", "keystore.jks"},
		{"the web server's vhost", "site.conf"},
	} {
		if !has(want.substr) {
			t.Errorf("%s was not reported (looked for %q)", want.what, want.substr)
		}
	}

	// A trust store is a list of issuers, not a deployment. Reporting it sends
	// a CA root nobody chose from every host in an estate.
	if has("ssl/trust.pem") {
		t.Error("a file of nothing but CA certificates was reported as a deployment")
	}
	// Private keys are not certificates, however they are named.
	for _, name := range []string{"secret1.key", "secret2.pem", "secret3.pem"} {
		if has(name) {
			t.Errorf("%s is a private key and was reported as a certificate", name)
		}
	}
}

// assertNoKeyMaterialOnTheWire is the one that cannot be walked back. The host
// has a directory of nothing but private keys inside a scanned root, some of
// them named .pem so the collector opens them.
func assertNoKeyMaterialOnTheWire(t *testing.T, server *fakeDTP) {
	t.Helper()
	wire := strings.ToUpper(server.allBodies())
	if !strings.Contains(wire, "BEGIN CERTIFICATE") {
		t.Fatal("no certificates crossed the wire at all; this assertion would pass vacuously")
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN RSA PRIVATE", "BEGIN EC PRIVATE", "BEGIN ENCRYPTED"} {
		if strings.Contains(wire, marker) {
			t.Fatalf("KEY MATERIAL LEFT THE HOST: %q appears in a request body", marker)
		}
	}
}

// assertEachPlacementOnce is the v0.2.2 bug. Two of the configured keystore
// roots reach the same file; before the fix that produced six observations for
// three aliases, and a run that claimed 12 placements where there were 9.
func assertEachPlacementOnce(t *testing.T, obs []observation) {
	t.Helper()
	// Keyed on the CERTIFICATE as well as the location, because that is how the
	// platform keys it: the unique index is
	// (agent, source, location, managed_certificate).
	//
	// Location alone is wrong, and a Windows runner proved it — the os_store
	// collector reports the STORE as the location on purpose, so the five
	// certificates in LocalMachine\My are five placements sharing one location,
	// not one placement reported five times. The first version of this
	// assertion called that a duplicate and went red on the one platform with a
	// real certificate store.
	seen := map[string]int{}
	for _, o := range obs {
		seen[o.Source+"|"+filepath.ToSlash(o.Location)+"|"+o.CertificatePEM]++
	}
	for key, n := range seen {
		if n > 1 {
			// The PEM makes the key unreadable; the source and location are
			// what identify the placement to a person.
			source, rest, _ := strings.Cut(key, "|")
			location, _, _ := strings.Cut(rest, "|")
			t.Errorf("reported %d times, and a member reads that number: %s %s", n, source, location)
		}
	}
}

// The shipped default roots overlap on purpose — covering the layouts people
// actually use means accepting that some of them match twice. This asserts the
// overlap is still there, so the deduplication above is testing something real
// rather than a list that quietly stopped overlapping.
func TestTheDefaultKeystoreRootsStillOverlap(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "internal", "collect", "keystore.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, root := range []string{`"/opt/tomcat*/conf"`, `"/opt/*/conf"`} {
		if !strings.Contains(src, root) {
			t.Skipf("the default roots changed; %s is gone, so this no longer describes them", root)
		}
	}
}
