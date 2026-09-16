package collect

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// socket is one TCP port this host is listening on, and the address it is bound
// to. The address matters: a listener bound to 10.0.0.5:443 does not answer on
// 127.0.0.1, so probing loopback for everything would miss it.
type socket struct {
	IP   net.IP
	Port int
}

// dialAddress is where to reach this listener from the host itself.
//
// A wildcard bind (0.0.0.0 or ::) answers on every interface, and loopback is
// the one of those that is certainly still ours a moment later — an address
// obtained from DHCP or a floating VIP may not be. A specific bind is dialled
// as given, because that is the only address it answers on.
func (s socket) dialAddress() string {
	ip := s.IP
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			ip = net.IPv4(127, 0, 0, 1)
		} else {
			ip = net.IPv6loopback
		}
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(s.Port))
}

// boundAddress is what the host's socket table says, reported verbatim so an
// operator reading the portfolio sees the bind they configured rather than the
// loopback address the agent happened to dial.
func (s socket) boundAddress() string {
	return net.JoinHostPort(s.IP.String(), strconv.Itoa(s.Port))
}

// procNetPaths are the kernel's TCP socket tables. Both are read: a host with
// IPv6 enabled lists a wildcard bind ONLY in tcp6 (a dual-stack listener on ::
// serves IPv4 too and never appears in tcp), so reading tcp alone misses the
// ordinary nginx on a modern box entirely.
var procNetPaths = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// procListenState is TCP_LISTEN as /proc spells it. Every other state is a
// connection, not a listener, and probing the far end of one would be the agent
// dialling a machine it was never asked to touch.
const procListenState = "0A"

// listeningSockets reads the host's own listening set.
//
// It returns an error rather than an empty list when it cannot read the socket
// table, and the caller turns that into an INCOMPLETE sweep: "this host listens
// on nothing" and "the agent could not find out" must not look the same, since
// the first would let DTP mark every previously-seen listener gone.
func listeningSockets() ([]socket, error) {
	if runtime.GOOS != "linux" {
		// Enumerating listeners without cgo is a per-platform exercise
		// (GetExtendedTcpTable on Windows, sysctl on the BSDs). Until those
		// exist, those hosts probe a well-known port list and say so by never
		// declaring this collector complete.
		//
		// Worded as a limitation rather than a fault because it reaches a
		// member's portfolio on every scan of every such host, and it is there
		// to explain a short list — not to report that something went wrong.
		return nil, fmt.Errorf(
			"this agent cannot read the socket table on %s, so it probed a list of well-known TLS ports instead; a listener on any other port will not appear",
			runtime.GOOS)
	}

	var (
		all  []socket
		errs []string
	)
	for _, path := range procNetPaths {
		f, err := os.Open(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		found, err := parseProcNet(f)
		_ = f.Close()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		all = append(all, found...)
	}

	// EITHER table failing means the set is partial, and a partial set is not a
	// sweep. Reporting what was read while claiming completeness is how a
	// listener that only appears in tcp6 gets marked absent.
	if len(errs) > 0 {
		return all, fmt.Errorf("reading the socket table: %s", strings.Join(errs, "; "))
	}
	return all, nil
}

// parseProcNet extracts the listening sockets from one /proc/net/tcp table.
func parseProcNet(r io.Reader) ([]socket, error) {
	scanner := bufio.NewScanner(r)
	var out []socket
	line := 0

	for scanner.Scan() {
		line++
		if line == 1 {
			continue // Column headings.
		}
		fields := strings.Fields(scanner.Text())
		// sl  local_address rem_address st …
		if len(fields) < 4 || fields[3] != procListenState {
			continue
		}
		local := strings.SplitN(fields[1], ":", 2)
		if len(local) != 2 {
			continue
		}
		ip, err := parseHexAddress(local[0])
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(local[1], 16, 16)
		if err != nil || port == 0 {
			continue
		}
		out = append(out, socket{IP: ip, Port: int(port)})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// parseHexAddress decodes an address as /proc writes it.
//
// The kernel prints each 32-bit word of the address with %08X, so on a
// little-endian host every word comes out byte-reversed: 127.0.0.1 is
// "0100007F", not "7F000001". Reading it as plain hex yields a real-looking
// address that is wrong — 1.0.0.127 — which is the kind of mistake that probes
// a stranger's machine rather than this host's, so the swap is not cosmetic.
//
// The agent is built only for amd64 and arm64, both little-endian. A big-endian
// port would need this to become a no-op.
func parseHexAddress(s string) (net.IP, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return nil, fmt.Errorf("address is %d bytes, not 4 or 16", len(raw))
	}

	out := make(net.IP, len(raw))
	for word := 0; word < len(raw); word += 4 {
		for b := 0; b < 4; b++ {
			out[word+b] = raw[word+3-b]
		}
	}
	return out, nil
}

// dedupe collapses the socket table to one entry per listener.
//
// A wildcard bind is keyed by PORT ALONE, deliberately. A host that listens on
// both 0.0.0.0:443 and [::]:443 has one web server, not two, and probing each
// would report the same certificate twice under locations that differ only by
// an address family nobody chose — then ask an operator to reason about which
// of the two is the real one. /proc/net/tcp is read before tcp6, so the IPv4
// form wins where both exist, and a host listed only in tcp6 keeps its own.
//
// A SPECIFIC bind stays distinct: 10.0.0.5:443 and 192.168.1.5:443 can be
// genuinely different services with genuinely different certificates.
func dedupe(sockets []socket) []socket {
	seen := make(map[string]bool, len(sockets))
	out := make([]socket, 0, len(sockets))
	for _, s := range sockets {
		key := s.boundAddress()
		if s.IP.IsUnspecified() {
			key = "*:" + strconv.Itoa(s.Port)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	// Ordered so a scan reports its findings the same way twice, which is what
	// makes two runs of `dtp-agent scan` comparable by eye.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].IP.String() < out[j].IP.String()
	})
	return out
}
