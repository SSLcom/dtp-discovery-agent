//go:build windows

package collect

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// Where HTTP.sys records which certificate answers on which address and port.
// This is the half of an IIS site's configuration that is not in
// applicationHost.config, and without it a site's certificate cannot be named.
const httpParametersKey = `SYSTEM\CurrentControlSet\Services\HTTP\Parameters`

// The three binding tables. Reading only the first finds the sites on a machine
// with one certificate and none of the sites on a machine with twenty, which is
// the wrong way round: SNI is what a busy host uses.
var sslBindingKeys = []string{
	"SslBindingInfo",    // address:port
	"SslSniBindingInfo", // address:port:hostheader
	"SslCcsBindingInfo", // central certificate store
}

// sslBinding is a certificate HTTP.sys will present, as the registry holds it.
type sslBinding struct {
	Thumbprint string
	StoreName  string
}

func applicationHostConfigPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "inetsrv", "config", "applicationHost.config")
}

// iisObservations joins the three places an IIS site's certificate is described.
//
// Returns nothing at all, with no error, on a machine without IIS — which is
// most of them.
func iisObservations() ([]Observation, []Error, bool) {
	configPath := applicationHostConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, true // No IIS here. Not a fault.
		}
		return nil, []Error{{Collector: SourceServerConfig, Location: configPath, Error: err.Error()}}, false
	}

	sites, err := parseApplicationHostConfig(data)
	if err != nil {
		return nil, []Error{{Collector: SourceServerConfig, Location: configPath, Error: err.Error()}}, false
	}
	if len(sites) == 0 {
		return nil, nil, true // IIS is installed and no site terminates TLS.
	}

	bindings, err := readSSLBindings()
	if err != nil {
		return nil, []Error{{
			Collector: SourceServerConfig, Location: httpParametersKey,
			Error: "IIS sites were found but their certificates could not be read: " + err.Error(),
		}}, false
	}

	// The certificates themselves. IIS binds to a thumbprint in a store, so
	// without the store there is a site, a binding and no certificate to report.
	certificates, storeErrs := certificatesByThumbprint(bindings)

	var (
		observations []Observation
		problems     []Error
	)
	problems = append(problems, storeErrs...)
	complete := len(storeErrs) == 0

	for _, site := range sites {
		for _, binding := range site.Bindings {
			thumbprint, store, found := lookupBinding(bindings, binding)
			if !found {
				// A site configured for https that HTTP.sys has no certificate
				// for. That is not the agent failing to look — it is a site
				// that will not serve, and somebody needs to know.
				problems = append(problems, Error{
					Collector: SourceServerConfig,
					Location:  "IIS:" + site.Name,
					Error:     "the https binding " + binding.Information + " has no certificate registered with HTTP.sys",
				})
				continue
			}
			entry, ok := certificates[thumbprint]
			if !ok {
				problems = append(problems, Error{
					Collector: SourceServerConfig,
					Location:  "IIS:" + site.Name,
					Error:     "binding " + binding.Information + " names certificate " + thumbprint + " in store " + store + ", which is not there",
				})
				complete = false
				continue
			}

			observations = append(observations, Observation{
				CertificatePEM: parse.EncodePEM([]*x509.Certificate{entry.Certificate}),
				Source:         SourceServerConfig,
				Location:       "IIS:" + site.Name,
				Binding: map[string]string{
					"server":              "iis",
					"site":                site.Name,
					"config_file":         configPath,
					"binding_information": binding.Information,
					"thumbprint":          thumbprint,
					"certificate_store":   store,
					"server_name":         binding.Host(),
				},
				PrivateKeyPresent:  entry.HasPrivateKey,
				PrivateKeyLocation: keyLocation(entry.Store, entry.HasPrivateKey),
				ObservedAt:         time.Now().UTC(),
			})
		}
	}
	return observations, problems, complete
}

func lookupBinding(bindings map[string]sslBinding, binding iisBinding) (thumbprint, store string, found bool) {
	for _, key := range binding.RegistryKeys() {
		if found, ok := bindings[strings.ToLower(key)]; ok {
			return found.Thumbprint, found.StoreName, true
		}
	}
	return "", "", false
}

// readSSLBindings reads every certificate HTTP.sys will present, from all three
// binding tables.
func readSSLBindings() (map[string]sslBinding, error) {
	out := map[string]sslBinding{}

	for _, table := range sslBindingKeys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, httpParametersKey+`\`+table, registry.READ)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				// A machine that has never had an SSL binding of this kind.
				// Ordinary, and not something to report.
				continue
			}
			return nil, err
		}

		names, err := key.ReadSubKeyNames(-1)
		if err != nil {
			_ = key.Close()
			return nil, err
		}
		for _, name := range names {
			binding, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			hash, _, hashErr := binding.GetBinaryValue("SslCertHash")
			store, _, storeErr := binding.GetStringValue("SslCertStoreName")
			_ = binding.Close()
			if hashErr != nil || len(hash) == 0 {
				continue
			}
			if storeErr != nil || store == "" {
				// The default when HTTP.sys records none. It is the personal
				// store, which is where IIS puts a certificate by default.
				store = "MY"
			}
			out[strings.ToLower(name)] = sslBinding{
				Thumbprint: strings.ToUpper(hex.EncodeToString(hash)),
				StoreName:  store,
			}
		}
		_ = key.Close()
	}
	return out, nil
}

// certificatesByThumbprint fetches the certificates the bindings point at, from
// the stores they name.
func certificatesByThumbprint(bindings map[string]sslBinding) (map[string]storeEntry, []Error) {
	wanted := map[string]bool{}
	stores := map[string]bool{}
	for _, binding := range bindings {
		wanted[binding.Thumbprint] = true
		stores[binding.StoreName] = true
	}

	found := map[string]storeEntry{}
	var problems []Error

	for store := range stores {
		// A binding names a store by its bare name; it is a LocalMachine store,
		// because HTTP.sys is a service and has no user hive to read.
		name := `LocalMachine\` + store
		entries, err := readWindowsStore(name)
		if err != nil {
			problems = append(problems, Error{
				Collector: SourceServerConfig, Location: name,
				Error: "an IIS binding names this store and it could not be read: " + err.Error(),
			})
			continue
		}
		for _, entry := range entries {
			if fingerprint := thumbprint(entry.Certificate); wanted[fingerprint] {
				found[fingerprint] = entry
			}
		}
	}
	return found, problems
}
