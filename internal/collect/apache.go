package collect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Apache configuration is line-oriented: one directive per line, sections in
// angle brackets, a trailing backslash continuing a line, and a # in the first
// non-blank column starting a comment. Include and IncludeOptional take globs
// and resolve them against ServerRoot, NOT against the including file — which
// is the difference between reading a Red Hat host's sites and reading none of
// them.

type apacheDirective struct {
	Name     string
	Args     []string
	Children []apacheDirective
	File     string
}

type apacheParser struct {
	r *configReader
	// serverRoot is what relative includes resolve against. It starts as the
	// main configuration's own directory, which is right on Debian, and is
	// replaced the moment a ServerRoot directive says otherwise — which is how
	// Red Hat's layout works, where httpd.conf lives in conf/ under a
	// ServerRoot of /etc/httpd and `IncludeOptional conf.d/*.conf` means
	// /etc/httpd/conf.d rather than /etc/httpd/conf/conf.d.
	serverRoot string
}

func parseApache(r *configReader, path string) ([]vhost, error) {
	p := &apacheParser{r: r, serverRoot: filepath.Dir(path)}
	nodes, err := p.file(path, 0)
	if err != nil {
		return nil, err
	}

	var hosts []vhost
	walkApache(nodes, nil, &hosts)
	return hosts, nil
}

func walkApache(nodes []apacheDirective, inherited []certificateRef, hosts *[]vhost) {
	// A certificate configured outside any VirtualHost belongs to the main
	// server, and every vhost that does not set its own inherits it.
	level := append(append([]certificateRef(nil), inherited...), apacheCertificates(nodes)...)

	for _, node := range nodes {
		if strings.EqualFold(node.Name, "VirtualHost") {
			*hosts = append(*hosts, apacheVirtualHost(node, level))
			continue
		}
		if len(node.Children) > 0 {
			// <IfModule mod_ssl.c>, <IfDefine>, <Macro>: a VirtualHost wrapped
			// in one is the ordinary way to write a conditional site, so these
			// are descended into rather than treated as opaque.
			walkApache(node.Children, level, hosts)
		}
	}
}

func apacheVirtualHost(node apacheDirective, inherited []certificateRef) vhost {
	host := vhost{Server: "apache", File: node.File, Listen: node.Args}

	if own := apacheCertificates(node.Children); len(own) > 0 {
		host.Certs = own
	} else {
		host.Certs = inherited
	}

	var walk func([]apacheDirective)
	walk = func(children []apacheDirective) {
		for _, child := range children {
			switch {
			case strings.EqualFold(child.Name, "ServerName"):
				// ServerName may carry a scheme and a port —
				// "https://www.example.com:443" is valid — and neither belongs
				// in a name.
				if len(child.Args) > 0 {
					host.Names = append(host.Names, apacheServerName(child.Args[0]))
				}
			case strings.EqualFold(child.Name, "ServerAlias"):
				for _, alias := range child.Args {
					host.Names = append(host.Names, apacheServerName(alias))
				}
			default:
				if len(child.Children) > 0 {
					walk(child.Children)
				}
			}
		}
	}
	walk(node.Children)
	return host
}

func apacheServerName(raw string) string {
	name := raw
	if i := strings.Index(name, "://"); i >= 0 {
		name = name[i+3:]
	}
	if i := strings.LastIndex(name, ":"); i > 0 && !strings.Contains(name[i:], "]") {
		name = name[:i]
	}
	return name
}

func apacheCertificates(nodes []apacheDirective) []certificateRef {
	var certs, keys, chains []string
	for _, node := range nodes {
		if len(node.Args) == 0 {
			continue
		}
		switch strings.ToLower(node.Name) {
		case "sslcertificatefile":
			certs = append(certs, node.Args[0])
		case "sslcertificatekeyfile":
			keys = append(keys, node.Args[0])
		case "sslcertificatechainfile":
			chains = append(chains, node.Args[0])
		}
	}
	return pairCertificates(certs, keys, chains)
}

// ── parsing ──────────────────────────────────────────────────────────────────

func (p *apacheParser) file(path string, depth int) ([]apacheDirective, error) {
	if depth > p.r.bounds.MaxDepth {
		return nil, fmt.Errorf("includes nested more than %d deep", p.r.bounds.MaxDepth)
	}
	data := p.r.read(path)
	if data == nil {
		return nil, nil
	}
	nodes, _, err := p.block(apacheLogicalLines(string(data)), 0, path, depth, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return nodes, nil
}

// block reads directives until the section named by `closing` ends.
func (p *apacheParser) block(lines []string, start int, file string, depth int, closing string) ([]apacheDirective, int, error) {
	var nodes []apacheDirective

	for i := start; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "</") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "</"), ">")
			if closing != "" && !strings.EqualFold(strings.TrimSpace(name), closing) {
				// Mismatched, which Apache would refuse to start on. Ending the
				// section anyway keeps the rest of the file readable rather
				// than throwing away every site after a typo.
				return nodes, i, nil
			}
			return nodes, i, nil
		}

		if strings.HasPrefix(line, "<") {
			inner := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			parts := apacheFields(inner)
			if len(parts) == 0 {
				continue
			}
			children, used, err := p.block(lines, i+1, file, depth, parts[0])
			if err != nil {
				return nodes, i, err
			}
			nodes = append(nodes, apacheDirective{
				Name: parts[0], Args: parts[1:], Children: children, File: file,
			})
			i = used
			continue
		}

		parts := apacheFields(line)
		if len(parts) == 0 {
			continue
		}
		switch strings.ToLower(parts[0]) {
		case "serverroot":
			if len(parts) > 1 {
				p.serverRoot = parts[1]
			}
		case "include", "includeoptional":
			if len(parts) > 1 {
				// Spliced in place: a VirtualHost in sites-enabled is the whole
				// configuration on a Debian host, and treating includes as
				// opaque would find nothing there.
				for _, match := range p.r.expand(parts[1], p.serverRoot) {
					included, err := p.file(match, depth+1)
					if err != nil {
						p.r.note(match, err)
						continue
					}
					nodes = append(nodes, included...)
				}
			}
		default:
			nodes = append(nodes, apacheDirective{Name: parts[0], Args: parts[1:], File: file})
		}
	}
	return nodes, len(lines), nil
}

// apacheLogicalLines joins continuations, so a directive split over four lines
// with trailing backslashes is read as the one directive it is.
func apacheLogicalLines(src string) []string {
	var (
		out     []string
		pending strings.Builder
	)
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasSuffix(line, "\\") {
			pending.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		pending.WriteString(line)
		out = append(out, pending.String())
		pending.Reset()
	}
	if pending.Len() > 0 {
		out = append(out, pending.String())
	}
	return out
}

// apacheFields splits a directive into its arguments, keeping a quoted argument
// whole. A path with a space in it is rare and entirely legal, and splitting it
// would produce a "configured certificate is missing" error for a site that is
// perfectly fine.
func apacheFields(line string) []string {
	var (
		fields  []string
		current strings.Builder
		quote   rune
		started bool
	)
	flush := func() {
		if started {
			fields = append(fields, current.String())
			current.Reset()
			started = false
		}
	}

	for _, ch := range line {
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteRune(ch)
		case ch == '"' || ch == '\'':
			quote = ch
			started = true
		case ch == ' ' || ch == '\t':
			flush()
		default:
			current.WriteRune(ch)
			started = true
		}
	}
	flush()
	return fields
}

// pairCertificates matches each certificate with the key and chain declared at
// the same position.
//
// BOTH servers allow several of each, in order, so one site can present an RSA
// certificate to an old client and an ECDSA one to everything else — and both
// read them positionally. Taking only the first, or pairing by proximity in the
// file, attaches the wrong key path to a certificate. The key path is the whole
// reason an operator opens this screen, and a wrong one sends them to look at a
// file that is not the one at risk.
func pairCertificates(certs, keys, chains []string) []certificateRef {
	refs := make([]certificateRef, 0, len(certs))
	for i, cert := range certs {
		if !isReadablePath(cert) {
			continue
		}
		ref := certificateRef{Certificate: cert}
		if i < len(keys) {
			ref.Key = keys[i]
		}
		if i < len(chains) {
			ref.Chain = chains[i]
		}
		refs = append(refs, ref)
	}
	return refs
}

// isReadablePath rejects the values that are configuration rather than a file:
// an nginx variable, a PKCS#11 URI, an inline data: certificate. The server
// would not open them as files either, so reporting one as a missing
// certificate would raise an alarm about a site that is working.
func isReadablePath(value string) bool {
	if value == "" || strings.ContainsAny(value, "$") {
		return false
	}
	for _, prefix := range []string{"engine:", "data:", "pkcs11:"} {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			return false
		}
	}
	return true
}
