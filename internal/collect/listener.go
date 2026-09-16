package collect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// ListenerBounds keeps the probe to something a host will not notice.
//
// Every probe is a connection to a live service on a machine the agent is a
// guest on, so the defaults are conservative: a handful at a time, each
// abandoned quickly, and a ceiling on how many are tried at all.
type ListenerBounds struct {
	// Ports, when set, REPLACES enumeration of the host's socket table. An
	// explicit list is a guess about what is listening, however well informed,
	// so a scan that uses one is never a complete sweep.
	Ports []int
	// ServerNames are sent as SNI, one probe each, after the probe that sends
	// none. A name-based virtual host answers a probe without SNI with its
	// DEFAULT certificate, so without these the other twenty sites on the box
	// are invisible. The server-config collector is what supplies them.
	ServerNames []string
	MaxProbes   int
	Timeout     time.Duration
	Concurrency int
}

// Well-known ports for hosts whose socket table the agent cannot read. Every
// one is IMPLICIT TLS — the handshake starts the moment the connection opens.
// The STARTTLS ports (25, 587, 143, 110) are deliberately absent: they need a
// protocol conversation before the handshake, so a bare ClientHello finds
// nothing there while looking exactly like a port that serves no certificate.
var wellKnownTLSPorts = []int{443, 465, 636, 853, 989, 990, 993, 995, 5986, 8443, 9443}

func (b ListenerBounds) withDefaults() ListenerBounds {
	if b.MaxProbes <= 0 {
		b.MaxProbes = 256
	}
	if b.Timeout <= 0 {
		b.Timeout = 5 * time.Second
	}
	if b.Concurrency <= 0 {
		b.Concurrency = 8
	}
	return b
}

// Listener finds certificates by asking the host's own TLS services for them.
//
// This is the only collector that reports what is actually BEING SERVED rather
// than what is on disk, and the difference is the point: a certificate renewed
// into /etc/ssl an hour ago protects nobody if nothing reloaded, and every
// other source would call that host healthy.
type Listener struct {
	Bounds ListenerBounds

	// enumerate replaces reading this host's socket table. Only tests set it.
	enumerate func() ([]socket, error)
}

func (c *Listener) Source() string { return SourceListener }

func (c *Listener) Collect(ctx context.Context) Result {
	b := c.Bounds.withDefaults()
	res := Result{Source: SourceListener, Completed: true}

	targets, swept := c.targets(b, &res)
	if !swept {
		// The probe list is a guess rather than this host's own listening set,
		// so its silence proves nothing, and nothing it found may later be used
		// to decide a listener stopped serving.
		res.Completed = false
	}
	if len(targets) > b.MaxProbes {
		targets = targets[:b.MaxProbes]
		res.Completed = false
		res.Errors = append(res.Errors, Error{
			Collector: SourceListener,
			Error:     fmt.Sprintf("this host listens on more than %d ports; only the first were probed", b.MaxProbes),
		})
	}

	c.probeAll(ctx, b, targets, &res)
	return res
}

// targets is what to probe, and whether that list is the host's OWN listening
// set rather than a guess.
func (c *Listener) targets(b ListenerBounds, res *Result) (targets []socket, swept bool) {
	if len(b.Ports) > 0 {
		for _, port := range b.Ports {
			targets = append(targets, socket{IP: net.IPv4(127, 0, 0, 1), Port: port})
		}
		return dedupe(targets), false
	}

	enumerate := c.enumerate
	if enumerate == nil {
		enumerate = listeningSockets
	}
	found, err := enumerate()
	if err != nil {
		// Fall back to the well-known ports so a Windows or macOS host still
		// reports the listener everyone has, rather than reporting nothing —
		// but a guess is not a sweep, so this returns false, and the reason is
		// shown to the member wondering why the list looks short.
		res.Errors = append(res.Errors, Error{Collector: SourceListener, Error: err.Error()})
		for _, port := range wellKnownTLSPorts {
			found = append(found, socket{IP: net.IPv4(127, 0, 0, 1), Port: port})
		}
		return dedupe(found), false
	}
	return dedupe(found), true
}

func (c *Listener) probeAll(ctx context.Context, b ListenerBounds, targets []socket, res *Result) {
	var (
		wg      sync.WaitGroup
		gate    = make(chan struct{}, b.Concurrency)
		results = make([]probeOutcome, len(targets))
	)

	for i, target := range targets {
		if ctx.Err() != nil {
			res.Completed = false
			break
		}
		wg.Add(1)
		go func(i int, target socket) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			// Each goroutine owns results[i] and nothing else, so the slice
			// needs no lock — it is read only after Wait.
			results[i] = c.probeTarget(ctx, b, target)
		}(i, target)
	}
	wg.Wait()

	for _, out := range results {
		res.Observations = append(res.Observations, out.observations...)
		res.Errors = append(res.Errors, out.errs...)
		if out.incomplete {
			res.Completed = false
		}
	}
}

type probeOutcome struct {
	observations []Observation
	errs         []Error
	incomplete   bool
}

// maxUnansweredNames stops a port that will not answer from costing one timeout
// per configured name. A machine hosting fifty sites behind a socket that hangs
// would otherwise hold a goroutine for fifty timeouts — four minutes on the
// defaults — to learn the same thing three probes already said.
const maxUnansweredNames = 3

// probeTarget asks one socket for its certificates: once carrying no SNI, then
// once for each name the configuration says it serves.
func (c *Listener) probeTarget(ctx context.Context, b ListenerBounds, target socket) probeOutcome {
	var out probeOutcome

	// The probe with no SNI comes first: it is what a client that knows only
	// the address receives, and on a single-site host it is the whole answer.
	names := append([]string{""}, b.ServerNames...)
	unanswered := 0

	for i, serverName := range names {
		obs, verdict, err := c.probeOne(ctx, b, target, serverName)

		switch verdict {
		case probeFound:
			out.observations = append(out.observations, *obs)
			unanswered = 0

		case probeNone:
			// ONLY THE FIRST PROBE CAN CONCLUDE ANYTHING ABOUT THE PORT. It
			// carries no SNI, so nothing answering it means nothing here speaks
			// TLS, and no name will change that — stopping saves a member's
			// machine a probe per site for every database and SSH daemon they
			// run.
			//
			// A LATER name drawing no certificate says only that this host does
			// not serve that name, which is ordinary: the configuration
			// collector reports every name on the machine, and they are not all
			// on every socket. Stopping there would abandon the sites after it
			// in the list while the sweep still counted as complete — and a
			// complete sweep that did not look is what marks a live
			// certificate gone.
			if i == 0 {
				return out
			}

		default: // probeUnknown
			out.incomplete = true
			out.errs = append(out.errs, Error{
				Collector: SourceListener,
				Location:  probeLocation(target, serverName),
				Error:     err.Error(),
			})
			// Not a reason to give up on the names. A default server configured
			// to refuse a handshake that carries no SNI — nginx's
			// ssl_reject_handshake, which is ordinary on a machine that does not
			// want to be enumerated — answers the first probe exactly like this
			// while serving every named site perfectly.
			unanswered++
			if unanswered >= maxUnansweredNames {
				return out
			}
		}
	}
	return out
}

// probeLocation names what was asked, so an error tells a member which probe
// failed rather than only which socket.
func probeLocation(target socket, serverName string) string {
	if serverName == "" {
		return target.dialAddress()
	}
	return target.dialAddress() + " (" + serverName + ")"
}

func (c *Listener) probeOne(ctx context.Context, b ListenerBounds, target socket, serverName string) (*Observation, verdict, error) {
	certs, state, v, err := handshake(ctx, target.dialAddress(), serverName, b.Timeout)
	if v != probeFound {
		return nil, v, err
	}

	binding := map[string]string{"address": target.boundAddress()}
	if serverName != "" {
		binding["server_name"] = serverName
	}
	if state != nil {
		binding["tls_version"] = tlsVersionName(state.Version)
		if state.NegotiatedProtocol != "" {
			binding["alpn"] = state.NegotiatedProtocol
		}
	}

	leaf := certs[0]
	return &Observation{
		CertificatePEM: parse.EncodePEM([]*x509.Certificate{leaf}),
		ChainPEM:       parse.EncodePEM(certs[1:]),
		Source:         SourceListener,
		Location:       target.dialAddress(),
		Binding:        binding,
		// A TLS listener necessarily holds a key, but this collector did not
		// SEE one: there is no path, mode or owner to report, and the field
		// exists so an operator can act on a key FILE. Inferring `true` would
		// put "key present" beside a blank location on every socket in the
		// estate and make the field useless where it does mean something.
		PrivateKeyPresent: false,
		ObservedAt:        time.Now().UTC(),
	}, probeFound, nil
}

// verdict is what a probe learned, and the three values are not interchangeable.
type verdict int

const (
	// probeFound: a certificate was presented.
	probeFound verdict = iota
	// probeNone: there is cleanly nothing to see — no TCP service, or a service
	// that does not speak TLS, or one that speaks it without a certificate.
	// Silence is the correct report.
	probeNone
	// probeUnknown: something is there and the probe could not finish with it.
	// This MUST make the sweep incomplete: a listener the agent could not talk
	// to is one whose certificate it did not see, not one that stopped serving,
	// and the difference decides whether DTP tells an operator a certificate
	// was removed from a host where nothing of the sort happened.
	probeUnknown
)

// handshake opens a TLS connection, takes the certificate, and closes it.
//
// It sends no application data — not a byte. The agent connects to live
// services on a machine it is a guest on, and a probe that spoke HTTP to
// whatever answered would be a scanner, not an inventory.
//
// The TCP connect is deliberately SEPARATE from the handshake. It is what makes
// the verdict structural rather than a guess at an errno: "the port did not
// accept a connection" and "the port accepted one and then did not speak TLS"
// are different facts, and reading them off error values would need
// ECONNREFUSED — which is a real errno on Unix and an unreachable placeholder
// constant on Windows, where the sockets layer returns WSAECONNREFUSED and
// errors.Is never matches. That mismatch would have made every Windows scan
// report a handful of invented errors for the well-known ports nothing is
// listening on.
func handshake(ctx context.Context, address, serverName string, timeout time.Duration) ([]*x509.Certificate, *tls.ConnectionState, verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		// A TIMEOUT is the ambiguous case: a local packet filter dropping the
		// probe looks exactly like this, and behind it there may well be a
		// listener with a certificate. Anything else — refused, unreachable —
		// means nothing accepted a connection, so there is no certificate here
		// to have missed.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil, probeUnknown, err
		}
		return nil, nil, probeNone, err
	}
	defer func() { _ = conn.Close() }()

	counted := &countingConn{Conn: conn}
	var captured []*x509.Certificate
	tlsConn := tls.Client(counted, &tls.Config{
		// The certificates worth finding are the BROKEN ones — expired,
		// self-signed, issued for another name. Verifying would reject exactly
		// the findings this collector exists to produce.
		InsecureSkipVerify: true, //nolint:gosec // the invalid certificate IS the finding
		ServerName:         serverName,
		// Forgotten listeners are old listeners, so the probe speaks down to
		// TLS 1.0 rather than skipping the hosts most likely to need finding.
		MinVersion: tls.VersionTLS10,
		// Still called when InsecureSkipVerify is set, and called as the
		// certificate ARRIVES rather than once the handshake has succeeded.
		// That is what makes a mutually authenticated listener visible: it will
		// refuse the agent for presenting no client certificate, but by then it
		// has already presented its own, and that certificate's expiry is a
		// fact an operator needs whether or not the agent was let in.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if cert, err := x509.ParseCertificate(raw); err == nil {
					captured = append(captured, cert)
				}
			}
			return nil
		},
	})

	hsErr := tlsConn.HandshakeContext(ctx)
	if len(captured) > 0 {
		state := tlsConn.ConnectionState()
		return captured, &state, probeFound, nil
	}
	if hsErr == nil {
		// TLS, completed, and no certificate offered: an anonymous cipher
		// suite. Nothing to inventory and nothing wrong.
		return nil, nil, probeNone, nil
	}
	// THE PEER SENT NOTHING AT ALL — whether it hung up or simply sat there
	// until the probe gave up. That is not an ambiguous result, it is a
	// definite one: a TLS implementation answers a ClientHello with a record
	// even when it is rejecting it, a ServerHello or an alert, and it does so
	// in milliseconds. A peer that accepted the connection and then said
	// nothing does not speak TLS. Postgres, Redis and DNS-over-TCP all behave
	// exactly this way — they are waiting for a message they would understand,
	// and the ClientHello is not one.
	//
	// THIS IS CHECKED BEFORE THE TIMEOUT, and the order is the whole point. An
	// earlier draft asked about the timeout first, on the reasoning that a peer
	// still thinking has not finished saying nothing. Run against a real
	// machine, that reasoning marked the sweep incomplete on a box whose only
	// sin was running a DNS resolver and a Redis — and an incomplete sweep is
	// one whose findings may never retire a placement, so the portfolio would
	// have gone on listing sites as served from machines they were moved off
	// months earlier, with nothing able to correct it.
	//
	// What this gives up is the TLS server so loaded it sends nothing at all
	// within the timeout. That server's certificate would be wrongly retired.
	// It is the rarer fault by a wide margin, and a longer --timeout is its
	// answer.
	if counted.bytesRead() == 0 {
		return nil, nil, probeNone, hsErr
	}
	// Out of time, having heard SOMETHING. The peer speaks a protocol that
	// answers, and the probe could not finish with it — so what it serves is
	// genuinely unknown, and this run must not conclude anything about it.
	var netErr net.Error
	if (errors.As(hsErr, &netErr) && netErr.Timeout()) || errors.Is(hsErr, context.DeadlineExceeded) {
		return nil, nil, probeUnknown, hsErr
	}
	// The first bytes back were not a TLS record — an HTTP server, an SSH
	// daemon announcing itself. Definitive, and the common case on a busy host.
	var recordHeader tls.RecordHeaderError
	if errors.As(hsErr, &recordHeader) {
		return nil, nil, probeNone, hsErr
	}
	return nil, nil, probeUnknown, hsErr
}

// countingConn records whether the peer ever said anything, which is what lets
// handshake tell "does not speak TLS" apart from "would not finish speaking
// TLS". Only the count is observed; no byte read here is retained.
type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *countingConn) bytesRead() int64 { return c.read.Load() }

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
