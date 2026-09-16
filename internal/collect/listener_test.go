package collect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS starts a TLS listener on a loopback port and returns that port.
func serveTLS(t *testing.T, cfg *tls.Config) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Complete the handshake, then close. Nothing is ever read,
				// which is also the assertion that the agent sends no
				// application data: a probe that did would hang here.
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveRaw starts a plain TCP listener that runs handle on each connection.
func serveRaw(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// collectPorts probes an explicit port list, as a host whose socket table the
// agent cannot read would.
func collectPorts(t *testing.T, bounds ListenerBounds, ports ...int) Result {
	t.Helper()
	bounds.Ports = ports
	if bounds.Timeout == 0 {
		bounds.Timeout = 3 * time.Second
	}
	c := &Listener{Bounds: bounds}
	return c.Collect(context.Background())
}

// collectSwept probes the same ports while claiming to have READ them off the
// host, which is what lets the sweep be complete.
func collectSwept(t *testing.T, bounds ListenerBounds, ports ...int) Result {
	t.Helper()
	if bounds.Timeout == 0 {
		bounds.Timeout = 3 * time.Second
	}
	c := &Listener{
		Bounds: bounds,
		enumerate: func() ([]socket, error) {
			var out []socket
			for _, p := range ports {
				out = append(out, socket{IP: net.IPv4(127, 0, 0, 1), Port: p})
			}
			return out, nil
		},
	}
	return c.Collect(context.Background())
}

// commonNames reads the observations back through the agent's own parser, so
// the test asserts on what DTP would receive rather than on what the fixture
// put in.
func commonNames(t *testing.T, res Result) []string {
	t.Helper()
	var names []string
	for _, o := range res.Observations {
		parsed, err := parse.Certificates([]byte(o.CertificatePEM))
		if err != nil || len(parsed.Certificates) == 0 {
			t.Fatalf("observation did not carry a parsable certificate: %v", err)
		}
		names = append(names, parsed.Certificates[0].Subject.CommonName)
	}
	return names
}

// errNoSocketTable stands in for a host whose listening set the agent cannot
// read — every Windows and macOS host today.
var errNoSocketTable = errors.New("reading the socket table: not available here")

// ── what the probe finds ─────────────────────────────────────────────────────

func TestReportsTheCertificateAListenerActuallyServes(t *testing.T) {
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "served.example.com")}})

	res := collectPorts(t, ListenerBounds{}, port)

	if got := commonNames(t, res); len(got) != 1 || got[0] != "served.example.com" {
		t.Fatalf("expected the served certificate, got %v (errors: %v)", got, res.Errors)
	}
	obs := res.Observations[0]
	if obs.Source != SourceListener {
		t.Errorf("source = %q, want %q", obs.Source, SourceListener)
	}
	if want := "127.0.0.1:" + strconv.Itoa(port); obs.Location != want {
		t.Errorf("location = %q, want %q", obs.Location, want)
	}
	if obs.Binding["tls_version"] == "" {
		t.Error("the negotiated TLS version is worth reporting and was not recorded")
	}
}

// A self-signed, expired or wrong-name certificate is the FINDING. A probe that
// verified would discard precisely the results this collector exists to
// produce, so this asserts the certificate comes back despite being untrusted
// and long expired.
func TestReportsACertificateNoClientWouldAccept(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired yesterday.
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})

	res := collectPorts(t, ListenerBounds{}, port)

	if got := commonNames(t, res); len(got) != 1 || got[0] != "expired.example.com" {
		t.Fatalf("an expired certificate is the finding, not something to skip: got %v", got)
	}
}

// The listener that demands a client certificate is the one an agent is least
// able to talk to and most needs to report: it is infrastructure, it is
// long-lived, and nobody is watching its expiry. The handshake fails; the
// certificate still arrived.
func TestReportsTheCertificateOfAListenerThatRefusesTheAgent(t *testing.T) {
	port := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, "mutual.example.com")},
		ClientAuth:   tls.RequireAnyClientCert,
	})

	res := collectPorts(t, ListenerBounds{}, port)

	if got := commonNames(t, res); len(got) != 1 || got[0] != "mutual.example.com" {
		t.Fatalf("a mutually authenticated listener must still yield its own certificate: got %v (errors %v)", got, res.Errors)
	}
}

// Without SNI a name-based virtual host answers with its default certificate,
// so every other site on the machine is invisible. This is the mechanism the
// server-config collector feeds.
func TestSNIFindsTheOtherSitesOnTheSameSocket(t *testing.T) {
	fallback := selfSigned(t, "default.example.com")
	alpha := selfSigned(t, "alpha.example.com")
	beta := selfSigned(t, "beta.example.com")

	port := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{fallback},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			switch hello.ServerName {
			case "alpha.example.com":
				return &alpha, nil
			case "beta.example.com":
				return &beta, nil
			default:
				return &fallback, nil
			}
		},
	})

	res := collectPorts(t, ListenerBounds{
		ServerNames: []string{"alpha.example.com", "beta.example.com"},
	}, port)

	got := strings.Join(commonNames(t, res), ",")
	want := "default.example.com,alpha.example.com,beta.example.com"
	if got != want {
		t.Fatalf("got %q, want %q (errors: %v)", got, want, res.Errors)
	}
	// The name asked for is what makes the observation actionable — three
	// certificates on one socket are otherwise indistinguishable.
	if res.Observations[1].Binding["server_name"] != "alpha.example.com" {
		t.Errorf("binding lost the server name: %v", res.Observations[1].Binding)
	}
	if res.Observations[0].Binding["server_name"] != "" {
		t.Errorf("the probe without SNI must not claim a server name: %v", res.Observations[0].Binding)
	}
}

// ── what the probe must NOT do ───────────────────────────────────────────────

// An observation carries a certificate and nothing else. This is the same
// property parse and transport enforce, asserted at the third place a
// certificate enters the agent.
func TestAnObservationCarriesNoKeyMaterial(t *testing.T) {
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "keyed.example.com")}})

	res := collectPorts(t, ListenerBounds{}, port)

	for _, o := range res.Observations {
		if strings.Contains(strings.ToUpper(o.CertificatePEM+o.ChainPEM), "PRIVATE KEY") {
			t.Fatal("key material reached an observation")
		}
		// The listener holds a key by definition but did not OBSERVE one: it
		// has no path, mode or owner to offer, and claiming otherwise would put
		// an unactionable "key present" on every socket in the estate.
		if o.PrivateKeyPresent {
			t.Error("the listener collector must not claim to have found a key")
		}
	}
}

// The agent connects to live services on a machine it is a guest on. A probe
// that spoke the application protocol to whatever answered would be a scanner.
func TestTheProbeSendsNoApplicationData(t *testing.T) {
	received := make(chan []byte, 1)
	port := serveRaw(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Read the ClientHello, then send a TLS-shaped refusal so the probe
		// stops rather than waiting. Anything read AFTER that would be the
		// agent talking out of turn.
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		first := append([]byte(nil), buf[:n]...)
		_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) // fatal handshake_failure
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n2, _ := conn.Read(buf)
		if n2 > 0 {
			received <- buf[:n2]
			return
		}
		received <- first[:0]
	})

	collectPorts(t, ListenerBounds{Timeout: time.Second}, port)

	select {
	case extra := <-received:
		if len(extra) > 0 {
			t.Fatalf("the probe sent %d bytes after the ClientHello: %q", len(extra), extra)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the fixture never saw the probe")
	}
}

// ── the completeness contract ────────────────────────────────────────────────

// An explicit port list is a guess about what is listening, however well
// informed. Only a list read off the host is a sweep, and only a sweep may let
// DTP conclude a listener stopped serving.
func TestAGuessedPortListIsNeverASweep(t *testing.T) {
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "guessed.example.com")}})

	if res := collectPorts(t, ListenerBounds{}, port); res.Completed {
		t.Fatal("probing a supplied port list must not be reported as a complete sweep")
	}
	if res := collectSwept(t, ListenerBounds{}, port); !res.Completed {
		t.Fatalf("reading the host's own socket table is a sweep: %v", res.Errors)
	}
}

// A host is full of ports that are not TLS. Reporting each as an error would
// bury the real findings and — far worse — mark the sweep incomplete, which
// stops this source ever retiring a placement again.
func TestPortsThatAreNotTLSAreSilentAndDoNotSpoilTheSweep(t *testing.T) {
	speaks := map[string]func(net.Conn){
		"an HTTP server": func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_, _ = conn.Read(make([]byte, 1024))
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		},
		"an SSH daemon": func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_, _ = conn.Read(make([]byte, 1024))
		},
		// The case that matters most: a line protocol that reads the
		// ClientHello, makes nothing of it, and hangs up without a word.
		// Postgres does this. Treating it as ambiguous would mark the sweep
		// incomplete on every host running one, forever.
		"a service that says nothing": func(conn net.Conn) {
			_, _ = conn.Read(make([]byte, 1024))
			_ = conn.Close()
		},
		// The same thing without the courtesy of hanging up: it waits for a
		// message it would understand, and a ClientHello is not one, so the
		// probe reaches its timeout having heard nothing. A DNS resolver, a
		// Redis — this was measured on an ordinary developer machine, where it
		// was what stopped the listener sweep ever completing.
		"a service that waits in silence": func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_, _ = conn.Read(make([]byte, 1024))
			time.Sleep(3 * time.Second)
		},
	}

	for name, handle := range speaks {
		t.Run(name, func(t *testing.T) {
			port := serveRaw(t, handle)
			res := collectSwept(t, ListenerBounds{Timeout: 2 * time.Second}, port)

			if len(res.Observations) != 0 {
				t.Errorf("invented %d observation(s) for a port serving no TLS", len(res.Observations))
			}
			if len(res.Errors) != 0 {
				t.Errorf("a port that is simply not TLS is not an error: %v", res.Errors)
			}
			if !res.Completed {
				t.Error("a port that is not TLS must not make the sweep incomplete")
			}
		})
	}
}

// Nothing listening at all is the commonest result of the well-known-port
// fallback, and it is not a finding either way.
func TestAClosedPortIsSilent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // Now certainly nothing is there.

	res := collectSwept(t, ListenerBounds{Timeout: 2 * time.Second}, port)
	if len(res.Errors) != 0 || len(res.Observations) != 0 {
		t.Fatalf("a closed port produced %v / %v", res.Observations, res.Errors)
	}
	if !res.Completed {
		t.Error("a closed port must not make the sweep incomplete")
	}
}

// The other half of the contract: something IS there, the probe could not
// finish with it, and that must be reported AND must stop the sweep counting as
// complete. A listener the agent could not talk to is one whose certificate it
// did not see — not one that stopped serving.
func TestAListenerTheProbeCannotFinishWithSpoilsTheSweep(t *testing.T) {
	port := serveRaw(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		// Answer with a TLS record header and then stall: the peer has spoken
		// TLS, so silence is not the explanation, and the probe must not guess.
		_, _ = conn.Read(make([]byte, 1024))
		_, _ = conn.Write([]byte{0x16, 0x03, 0x03, 0x01, 0x00})
		time.Sleep(3 * time.Second)
	})

	res := collectSwept(t, ListenerBounds{Timeout: 500 * time.Millisecond}, port)

	if res.Completed {
		t.Fatal("a probe that could not finish must not report a complete sweep")
	}
	if len(res.Errors) == 0 {
		t.Fatal("a member wondering why a listener is missing has to be told why")
	}
}

func TestTheWellKnownPortFallbackExplainsItself(t *testing.T) {
	c := &Listener{
		Bounds:    ListenerBounds{Timeout: 200 * time.Millisecond, Concurrency: 16},
		enumerate: func() ([]socket, error) { return nil, errNoSocketTable },
	}
	res := c.Collect(context.Background())

	if res.Completed {
		t.Error("a guessed port list is not a sweep")
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Error, "socket table") {
		t.Fatalf("the reason the list is a guess must reach the member: %v", res.Errors)
	}
}

// The other way a probe fails to finish, and the one a timeout test does not
// reach: the peer IS a TLS server and rejects the handshake outright. A
// listener that will only negotiate ciphers this Go release dropped answers
// exactly like this, and it is precisely the ageing appliance whose certificate
// nobody is tracking. Its alert must be reported, not read as "no TLS here".
func TestAListenerThatRejectsTheHandshakeIsReportedNotIgnored(t *testing.T) {
	port := serveRaw(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 4096))
		// A fatal alert: record type 21, TLS 1.2, level fatal, handshake_failure.
		_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	})

	res := collectSwept(t, ListenerBounds{Timeout: 2 * time.Second}, port)

	if res.Completed {
		t.Error("a TLS listener the agent could not negotiate with is unseen, not absent")
	}
	if len(res.Errors) == 0 {
		t.Fatal("the rejection must reach the member who is wondering where the certificate went")
	}
	if !strings.Contains(res.Errors[0].Error, "handshake failure") {
		t.Errorf("the error should say what the listener said: %q", res.Errors[0].Error)
	}
}
