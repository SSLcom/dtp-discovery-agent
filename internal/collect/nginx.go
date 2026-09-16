package collect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// nginx configuration is a tree of directives. A directive is a name, some
// arguments, and then either a semicolon or a block in braces. Comments run
// from an unquoted # to the end of the line, and arguments may be quoted.
//
// Only the shape matters here, not the meaning of any directive but a handful —
// so this is a tokeniser and a bracket matcher rather than an nginx.

type nginxDirective struct {
	Name     string
	Args     []string
	Children []nginxDirective
	File     string
}

// parseNginx reads a main configuration file and returns the sites it declares.
func parseNginx(r *configReader, path string) ([]vhost, error) {
	tree, err := nginxParseFile(r, path, 0)
	if err != nil {
		return nil, err
	}

	var hosts []vhost
	// ssl_certificate at http level is inherited by every server that does not
	// set its own, and plenty of single-site machines are configured that way.
	// A server block that inherits still presents a certificate, and an
	// inventory that only looked inside server blocks would call that host
	// bare.
	walkNginx(tree, nginxContext{}, &hosts)
	return hosts, nil
}

// nginxContext is what a server block inherits from the blocks around it.
type nginxContext struct {
	certs []certificateRef
}

func walkNginx(nodes []nginxDirective, inherited nginxContext, hosts *[]vhost) {
	// Directives at this level, before descending: an http block's
	// ssl_certificate applies to the server blocks inside it.
	level := inherited
	level.certs = append(append([]certificateRef(nil), inherited.certs...), nginxCertificates(nodes)...)

	for _, node := range nodes {
		switch node.Name {
		case "server":
			*hosts = append(*hosts, nginxServer(node, level))
		case "http", "stream", "mail":
			walkNginx(node.Children, level, hosts)
		default:
			if len(node.Children) > 0 {
				walkNginx(node.Children, level, hosts)
			}
		}
	}
}

func nginxServer(node nginxDirective, inherited nginxContext) vhost {
	host := vhost{Server: "nginx", File: node.File}

	own := nginxCertificates(node.Children)
	if len(own) > 0 {
		host.Certs = own
	} else {
		// Inherited from http { }. The site serves it just the same.
		host.Certs = inherited.certs
	}

	for _, child := range node.Children {
		switch child.Name {
		case "server_name":
			host.Names = append(host.Names, child.Args...)
		case "listen":
			host.Listen = append(host.Listen, strings.Join(child.Args, " "))
		}
	}
	return host
}

// nginxCertificates collects the ssl_certificate and ssl_certificate_key
// directives at one level, in order, for pairCertificates to match up.
func nginxCertificates(nodes []nginxDirective) []certificateRef {
	var certs, keys []string
	for _, node := range nodes {
		switch node.Name {
		case "ssl_certificate":
			if len(node.Args) > 0 {
				certs = append(certs, node.Args[0])
			}
		case "ssl_certificate_key":
			if len(node.Args) > 0 {
				keys = append(keys, node.Args[0])
			}
		}
	}

	return pairCertificates(certs, keys, nil)
}

// ── tokenising ───────────────────────────────────────────────────────────────

func nginxParseFile(r *configReader, path string, depth int) ([]nginxDirective, error) {
	if depth > r.bounds.MaxDepth {
		return nil, fmt.Errorf("includes nested more than %d deep", r.bounds.MaxDepth)
	}
	data := r.read(path)
	if data == nil {
		return nil, nil
	}

	tokens := nginxTokenize(string(data))
	nodes, _, err := nginxParseBlock(r, tokens, path, depth)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return nodes, nil
}

type nginxToken struct {
	text  string
	punct bool // one of { } ;
}

func nginxTokenize(src string) []nginxToken {
	var (
		tokens  []nginxToken
		current strings.Builder
		quote   rune
	)
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, nginxToken{text: current.String()})
			current.Reset()
		}
	}

	runes := []rune(src)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		if quote != 0 {
			// A backslash escapes the next character inside quotes — but ONLY
			// the characters that need escaping.
			//
			// nginx itself drops the backslash before anything at all, so
			// "C:\Users\nginx\ssl\site.pem" reads as "C:Usersnginxsslsite.pem"
			// there too. This agent deliberately does not follow it that far.
			// Its job is to find the file, a Windows path is the only place the
			// difference shows up, and reading it nginx's way turns every
			// quoted path on a Windows host into a "configured certificate is
			// missing" alarm about a site that is serving perfectly.
			if ch == '\\' && i+1 < len(runes) && needsEscaping(runes[i+1]) {
				i++
				current.WriteRune(runes[i])
				continue
			}
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteRune(ch)
			continue
		}

		switch {
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#':
			// A comment runs to the end of the line. Only outside quotes: a #
			// is legal inside a quoted path.
			flush()
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case ch == '{' || ch == '}' || ch == ';':
			flush()
			tokens = append(tokens, nginxToken{text: string(ch), punct: true})
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			flush()
		default:
			current.WriteRune(ch)
		}
	}
	flush()
	return tokens
}

// needsEscaping is the set a backslash is meaningful before: the quote
// characters, itself, and nginx's variable marker.
func needsEscaping(r rune) bool {
	switch r {
	case '"', '\'', '\\', '$':
		return true
	}
	return false
}

// nginxParseBlock consumes tokens until the block ends, returning what it read
// and how many tokens it used.
func nginxParseBlock(r *configReader, tokens []nginxToken, file string, depth int) ([]nginxDirective, int, error) {
	var (
		nodes []nginxDirective
		words []string
		i     int
	)

	for i = 0; i < len(tokens); i++ {
		token := tokens[i]
		if !token.punct {
			words = append(words, token.text)
			continue
		}

		switch token.text {
		case ";":
			if len(words) == 0 {
				continue // A stray semicolon. nginx would complain; the agent need not.
			}
			if words[0] == "include" && len(words) > 1 {
				// Splice the included files in HERE rather than recording the
				// directive: an ssl_certificate in an included file belongs to
				// the block that included it, and treating includes as opaque
				// would miss every site on a Debian box, where sites-enabled is
				// the entire configuration.
				for _, match := range r.expand(words[1], filepath.Dir(file)) {
					included, err := nginxParseFile(r, match, depth+1)
					if err != nil {
						r.note(match, err)
						continue
					}
					nodes = append(nodes, included...)
				}
			} else {
				nodes = append(nodes, nginxDirective{Name: words[0], Args: words[1:], File: file})
			}
			words = nil

		case "{":
			if len(words) == 0 {
				return nodes, i, fmt.Errorf("a block opened with no directive")
			}
			children, used, err := nginxParseBlock(r, tokens[i+1:], file, depth)
			if err != nil {
				return nodes, i, err
			}
			nodes = append(nodes, nginxDirective{
				Name: words[0], Args: words[1:], Children: children, File: file,
			})
			i += used + 1
			words = nil

		case "}":
			return nodes, i, nil
		}
	}
	return nodes, i, nil
}
