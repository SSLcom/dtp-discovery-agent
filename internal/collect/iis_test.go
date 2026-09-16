package collect

import (
	"strings"
	"testing"
)

// Trimmed from a real applicationHost.config: the element nesting, the
// attribute spellings and the shape of a bindingInformation are as IIS writes
// them.
const applicationHostConfig = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <applicationPools>
      <add name="DefaultAppPool" />
    </applicationPools>
    <sites>
      <site name="Default Web Site" id="1" serverAutoStart="true">
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
        </application>
        <bindings>
          <binding protocol="http" bindingInformation="*:80:" />
          <binding protocol="https" bindingInformation="*:443:" sslFlags="0" />
        </bindings>
      </site>
      <site name="shop.example.com" id="2">
        <bindings>
          <binding protocol="https" bindingInformation="*:443:shop.example.com" sslFlags="1" />
          <binding protocol="https" bindingInformation="10.0.0.5:8443:shop.example.com" sslFlags="1" />
        </bindings>
      </site>
      <site name="plain.example.com" id="3">
        <bindings>
          <binding protocol="http" bindingInformation="*:80:plain.example.com" />
        </bindings>
      </site>
    </sites>
  </system.applicationHost>
</configuration>`

func TestReadsTheSitesOutOfApplicationHostConfig(t *testing.T) {
	sites, err := parseApplicationHostConfig([]byte(applicationHostConfig))
	if err != nil {
		t.Fatal(err)
	}

	// A site with no https binding has no certificate, and reporting it as a
	// placement with none would be a finding about nothing.
	if len(sites) != 2 {
		var names []string
		for _, s := range sites {
			names = append(names, s.Name)
		}
		t.Fatalf("got %v, want the two sites that terminate TLS", names)
	}
	if sites[0].Name != "Default Web Site" || len(sites[0].Bindings) != 1 {
		t.Errorf("first site = %q with %d bindings", sites[0].Name, len(sites[0].Bindings))
	}
	if len(sites[1].Bindings) != 2 {
		t.Errorf("a site answers on as many endpoints as it is given: got %d", len(sites[1].Bindings))
	}
}

// IIS writes an address, a port and a host header into one string, using "*"
// for "any address" — while HTTP.sys records the same binding under 0.0.0.0.
// Reading either spelling wrongly means looking up a certificate that is filed
// under a name the agent never asks for.
func TestABindingInformationIsSplitTheWayHTTPsysFilesIt(t *testing.T) {
	cases := map[string]struct{ address, port, host string }{
		"*:443:":                     {"0.0.0.0", "443", ""},
		"*:443:www.example.com":      {"0.0.0.0", "443", "www.example.com"},
		"10.0.0.5:8443:shop.example": {"10.0.0.5", "8443", "shop.example"},
		"*::":                        {"0.0.0.0", "443", ""},
		"192.168.1.1:443:":           {"192.168.1.1", "443", ""},
	}
	for information, want := range cases {
		t.Run(information, func(t *testing.T) {
			b := iisBinding{Information: information}
			if b.Address() != want.address || b.Port() != want.port || b.Host() != want.host {
				t.Errorf("got %s / %s / %q, want %s / %s / %q",
					b.Address(), b.Port(), b.Host(), want.address, want.port, want.host)
			}
		})
	}
}

// On a host with twenty sites behind one address, the address-only entry is the
// FALLBACK certificate. Looking there first would report every one of those
// twenty sites as serving it, and the nineteen real certificates would be
// invisible — the same failure as probing a listener without SNI.
func TestTheMostSpecificBindingIsTriedFirst(t *testing.T) {
	sni := iisBinding{Information: "*:443:shop.example.com"}
	keys := sni.RegistryKeys()

	if len(keys) == 0 || !strings.HasSuffix(keys[0], ":shop.example.com") {
		t.Fatalf("keys = %v, want the host-specific entry first", keys)
	}
	// The address-only fallback is still tried, because a site can perfectly
	// well have a host header and a non-SNI binding.
	var hasFallback bool
	for _, k := range keys {
		if k == "0.0.0.0:443" {
			hasFallback = true
		}
	}
	if !hasFallback {
		t.Errorf("keys = %v, want the address-only entry as a fallback", keys)
	}

	// A binding with no host header has no specific entry to look for.
	plain := iisBinding{Information: "*:443:"}
	for _, k := range plain.RegistryKeys() {
		if strings.Count(k, ":") > 1 {
			t.Errorf("a binding with no host header asked for an SNI entry: %v", plain.RegistryKeys())
		}
	}
}

func TestAConfigurationThatIsNotXMLIsRefused(t *testing.T) {
	if _, err := parseApplicationHostConfig([]byte("<configuration")); err == nil {
		t.Error("a truncated configuration was accepted")
	}
}

// A machine without IIS is most machines. It has to be silent and it has to
// leave the sweep alone.
func TestWithoutIISNothingIsReported(t *testing.T) {
	observations, problems, complete := iisObservations()
	if len(observations) != 0 && len(problems) == 0 && !complete {
		t.Error("unreachable on a machine with IIS; this is the no-IIS path")
	}
	if !complete && len(problems) == 0 {
		t.Error("an incomplete sweep with nothing to say is a sweep nobody can act on")
	}
}
