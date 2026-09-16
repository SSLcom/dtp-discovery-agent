package collect

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// IIS keeps a site's certificate NOWHERE NEAR its configuration, and that shapes
// everything here.
//
// applicationHost.config lists the sites and their bindings — the protocol, the
// address, the port, the host header — and stops there. The certificate a
// binding presents is held by HTTP.sys, in the registry, keyed by address and
// port, as a thumbprint into a certificate store. So reading a site's
// certificate means three things joined: the configuration file for the site's
// NAME, the registry for its THUMBPRINT, and the certificate store for the
// certificate itself.
//
// The XML half lives here, out of the Windows build-tag files, so it is parsed
// on every runner rather than only the one where the rest of it can run.

// iisSite is one site as applicationHost.config declares it.
type iisSite struct {
	Name     string
	Bindings []iisBinding
}

// iisBinding is one endpoint a site answers on.
type iisBinding struct {
	// Information is IIS's own spelling: "address:port:hostheader", where the
	// address is often "*" and the host header is often empty.
	Information string
	Protocol    string
}

// Address, Port and Host split an IIS bindingInformation, translating its "*"
// into the 0.0.0.0 that HTTP.sys records in the registry.
func (b iisBinding) Address() string {
	parts := strings.SplitN(b.Information, ":", 3)
	if len(parts) == 0 || parts[0] == "" || parts[0] == "*" {
		return "0.0.0.0"
	}
	return parts[0]
}

func (b iisBinding) Port() string {
	parts := strings.SplitN(b.Information, ":", 3)
	if len(parts) < 2 || parts[1] == "" {
		return "443"
	}
	return parts[1]
}

func (b iisBinding) Host() string {
	parts := strings.SplitN(b.Information, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// RegistryKeys are the names HTTP.sys might have filed this binding under, most
// specific first.
//
// A binding with a host header is an SNI binding and is recorded under
// address:port:host; one without is recorded under address:port alone. Trying
// the specific name first matters on a host with twenty sites behind one
// address, where the address-only entry is the fallback certificate and every
// site would otherwise be reported as serving it.
func (b iisBinding) RegistryKeys() []string {
	address, port, host := b.Address(), b.Port(), b.Host()
	if host != "" {
		return []string{
			address + ":" + port + ":" + host,
			"0.0.0.0:" + port + ":" + host,
			address + ":" + port,
		}
	}
	return []string{address + ":" + port, "0.0.0.0:" + port}
}

// parseApplicationHostConfig reads the sites out of IIS's configuration.
func parseApplicationHostConfig(data []byte) ([]iisSite, error) {
	var doc struct {
		Sites struct {
			Site []struct {
				Name     string `xml:"name,attr"`
				Bindings struct {
					Binding []struct {
						Protocol    string `xml:"protocol,attr"`
						Information string `xml:"bindingInformation,attr"`
					} `xml:"binding"`
				} `xml:"bindings"`
			} `xml:"site"`
		} `xml:"system.applicationHost>sites"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("reading applicationHost.config: %w", err)
	}

	sites := make([]iisSite, 0, len(doc.Sites.Site))
	for _, site := range doc.Sites.Site {
		out := iisSite{Name: site.Name}
		for _, binding := range site.Bindings.Binding {
			// Only the ones that terminate TLS. A site's plain HTTP binding has
			// no certificate, and reporting it as a placement with none would be
			// a finding about nothing.
			if !strings.EqualFold(binding.Protocol, "https") {
				continue
			}
			out.Bindings = append(out.Bindings, iisBinding{
				Information: binding.Information, Protocol: binding.Protocol,
			})
		}
		if len(out.Bindings) > 0 {
			sites = append(sites, out)
		}
	}
	return sites, nil
}
