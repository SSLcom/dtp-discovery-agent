package collect

import (
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Rows copied verbatim from a running Linux host, checked line by line against
// what `ss -ltn` said about the same machine at the same moment. Inventing this
// fixture from the format documentation would have tested the parser against
// the same belief that wrote it.
const realProcNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1539 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 98375 1 0000000000000000 100 0 0 10 0
   1: FEFFFF0A:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6154 1 0000000000000000 100 0 0 10 0
   2: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 4399 1 0000000000000000 100 0 0 10 5
   3: 0100007F:C63D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9494458 1 0000000000000000 100 0 0 10 0
   4: 0100007F:1F90 0100007F:D14E 01 00000000:00000000 00:00000000 00000000  1000        0 9494459 1 0000000000000000 100 0 0 10 0
`

const realProcNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:18EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 13925 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:4965 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 3804 1 0000000000000000 100 0 0 10 0
`

// THE FAILURE THIS GUARDS IS NOT A CRASH. The kernel prints each 32-bit word of
// the address with %08X, so on a little-endian host every word arrives
// byte-reversed. Read as plain hex, 127.0.0.1 becomes 1.0.0.127 — a valid,
// routable, entirely real address belonging to somebody else. The agent would
// then dial a stranger's machine on every scan while looking like it was
// probing localhost, and nothing about the output would appear wrong.
func TestTheSocketTableIsReadInTheKernelsByteOrder(t *testing.T) {
	got, err := parseProcNet(strings.NewReader(realProcNetTCP))
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"127.0.0.1:5433", "10.255.255.254:53", "127.0.0.54:53", "127.0.0.1:50749"}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %v", len(got), len(want), addresses(got))
	}
	for i, w := range want {
		if got[i].boundAddress() != w {
			t.Errorf("socket %d = %s, want %s", i, got[i].boundAddress(), w)
		}
	}
}

// Only listeners. Row 4 of the fixture is an ESTABLISHED connection; probing
// the far end of one would be the agent dialling a machine nobody asked it to
// touch.
func TestOnlyListeningSocketsAreProbed(t *testing.T) {
	got, err := parseProcNet(strings.NewReader(realProcNetTCP))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if s.Port == 8080 {
			t.Fatalf("an established connection was read as a listener: %s", s.boundAddress())
		}
	}
}

func TestIPv6SocketsAreReadToo(t *testing.T) {
	got, err := parseProcNet(strings.NewReader(realProcNetTCP6))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[::]:6379", "[::1]:18789"}
	if a := addresses(got); len(a) != 2 || a[0] != want[0] || a[1] != want[1] {
		t.Fatalf("got %v, want %v", a, want)
	}
}

func TestWildcardBindsAreDialledOnLoopback(t *testing.T) {
	cases := map[string]struct{ bound, dial string }{
		"IPv4 wildcard": {"0.0.0.0:443", "127.0.0.1:443"},
		"IPv6 wildcard": {"[::]:443", "[::1]:443"},
		// A specific bind answers on that address and nowhere else, so
		// redirecting it to loopback would probe the wrong thing — or nothing.
		"a specific address": {"10.0.0.5:443", "10.0.0.5:443"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			host, _, _ := net.SplitHostPort(tc.bound)
			s := socket{IP: net.ParseIP(host), Port: 443}
			if got := s.dialAddress(); got != tc.dial {
				t.Errorf("dialAddress() = %s, want %s", got, tc.dial)
			}
			if got := s.boundAddress(); got != tc.bound {
				t.Errorf("boundAddress() = %s, want %s", got, tc.bound)
			}
		})
	}
}

// One web server listening on both families is one web server. Reporting its
// certificate twice, at two locations differing only by an address family
// nobody chose, asks an operator to work out which is the real one.
func TestOneListenerOnBothFamiliesIsProbedOnce(t *testing.T) {
	got := dedupe([]socket{
		{IP: net.IPv4zero, Port: 443},
		{IP: net.IPv6unspecified, Port: 443},
		// Distinct addresses can be distinct services with distinct
		// certificates, so these must survive.
		{IP: net.ParseIP("10.0.0.5"), Port: 8443},
		{IP: net.ParseIP("10.0.0.6"), Port: 8443},
	})
	if a := addresses(got); len(a) != 3 || a[0] != "0.0.0.0:443" {
		t.Fatalf("got %v, want the v4 wildcard plus both specific binds", a)
	}
}

func TestAMalformedRowIsSkippedRatherThanFatal(t *testing.T) {
	// A kernel that grows a column, a truncated read, a row from the future.
	// None of it should cost the agent the rest of the table.
	table := `  sl  local_address rem_address   st
   0: nonsense 00000000:0000 0A
   1: 0100007F 00000000:0000 0A
   2: 0100007F:0000 00000000:0000 0A
   3: 0100007F:1539 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 100 0 0 10 0
`
	got, err := parseProcNet(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	if a := addresses(got); len(a) != 1 || a[0] != "127.0.0.1:5433" {
		t.Fatalf("got %v, want only the one good row", a)
	}
}

func TestARejectedAddressIsNotGuessedAt(t *testing.T) {
	for _, bad := range []string{"", "zz", "0100007", "0100007FF", "0100007F0100007F"} {
		if ip, err := parseHexAddress(bad); err == nil {
			t.Errorf("parseHexAddress(%q) invented %s instead of failing", bad, ip)
		}
	}
}

// The strongest check available: read THIS host's socket table through the
// whole path — file locations, state filter, byte order — and look for a port
// this test itself opened a moment ago. A fixture can only ever confirm what
// its author believed the format to be.
func TestFindsAPortThisTestIsListeningOn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("the socket table is only readable on linux, not %s", runtime.GOOS)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	sockets, err := listeningSockets()
	if err != nil {
		t.Fatalf("reading this host's socket table: %v", err)
	}
	for _, s := range sockets {
		if s.Port == port && s.IP.String() == "127.0.0.1" {
			return
		}
	}
	t.Fatalf("the kernel says this process listens on 127.0.0.1:%d; the parser found %v", port, addresses(sockets))
}

func addresses(sockets []socket) []string {
	out := make([]string, 0, len(sockets))
	for _, s := range sockets {
		out = append(out, s.boundAddress())
	}
	return out
}

// A dual-stack listener on :: serves IPv4 too and is listed ONLY in
// /proc/net/tcp6. That is the ordinary nginx on a modern box, so an agent that
// read /proc/net/tcp alone would find the whole web tier of an estate empty
// while reporting a clean, complete sweep.
func TestFindsAWildcardListenerListedOnlyInTheIPv6Table(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("the socket table is only readable on linux, not %s", runtime.GOOS)
	}

	ln, err := net.Listen("tcp", ":0") // Binds ::, dual-stack.
	if err != nil {
		t.Skipf("this host cannot open a wildcard listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	inTCP4, err := parseProcNetFile(t, "/proc/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	if hasPort(inTCP4, port) {
		t.Skip("this host listed the wildcard bind in the IPv4 table, so it cannot show the gap")
	}

	sockets, err := listeningSockets()
	if err != nil {
		t.Fatalf("reading this host's socket table: %v", err)
	}
	if !hasPort(sockets, port) {
		t.Fatalf("a wildcard listener on port %d was missed; found %v", port, addresses(sockets))
	}
}

// Half a socket table is not a sweep. Reporting what was read while claiming
// completeness is exactly how a listener that appears only in the table the
// agent could not open gets marked absent.
func TestAnUnreadableTableIsAnErrorRatherThanAShortList(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("the socket table is only readable on linux, not %s", runtime.GOOS)
	}

	original := procNetPaths
	defer func() { procNetPaths = original }()
	procNetPaths = []string{"/proc/net/tcp", "/proc/net/tcp-does-not-exist"}

	sockets, err := listeningSockets()
	if err == nil {
		t.Fatal("a table the agent could not open must be reported, not quietly dropped")
	}
	// What WAS read is still returned: those listeners are worth probing. It is
	// only the claim of completeness that has to go.
	if len(sockets) == 0 {
		t.Error("the readable table's listeners should still be probed")
	}
}

func parseProcNetFile(t *testing.T, path string) ([]socket, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseProcNet(f)
}

func hasPort(sockets []socket, port int) bool {
	for _, s := range sockets {
		if s.Port == port {
			return true
		}
	}
	return false
}
