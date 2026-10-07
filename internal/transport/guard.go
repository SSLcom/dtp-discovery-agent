package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// ErrKeyMaterialOutbound is refused locally and never sent.
var ErrKeyMaterialOutbound = errors.New("refusing to transmit private key material")

// guardOutbound is the last thing between this process and the network.
//
// IT SHOULD NEVER FIRE. collect.Observation has no field for key material and
// parse re-encodes certificates from their parsed DER rather than copying bytes
// out of a file, so there is no path by which a key reaches a request body. This
// exists because "should never" is a claim about today's code, and the cost of
// being wrong once is a customer's private key in someone else's database.
//
// The server refuses such a payload too, with a 422. That is the wrong place to
// find out: by then it has crossed the network and been written to a log on the
// way. A guard that fires here means a bug to fix; a guard that fires there
// means an incident to disclose.
//
// IT LOOKS AT EACH STRING IN THE BODY, NOT AT THE BODY AS TEXT. A firing guard
// refuses the whole request, and an inventory page is mostly NAMES the host
// chose: paths, keystore aliases, server names, error text. The guard used to
// match "private key" anywhere in the marshalled body, so one directory called
// "Private Key Backups" in a scanned root, or a keystore alias "server private
// key", refused every page of every run on that host — its whole inventory
// unreported, for as long as the name stayed, with nothing to fix but a rename
// nobody would think of. Measured with the v0.5.0 candidate binary.
//
// So the two kinds of field are held to different tests:
//
//   - a field named *_pem carries certificates, and gets the broad test,
//     substring fallback and all: anything there that so much as mentions a
//     private key is wrong, and a truncated key must not slip through because
//     pem.Decode rejected it.
//   - every other string (and every map key) is refused only for a key's
//     ARMOR — a "-----BEGIN … PRIVATE KEY-----" line. That is what a key looks
//     like wherever it ends up, and no path or alias carries one by accident.
//     (JSON escapes the newlines, which is why this has to decode the body: a
//     PEM block is not a PEM block inside a JSON string literal.)
func guardOutbound(body []byte) error {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Never expected — the body was just marshalled — but a body this
		// cannot walk gets the broad test rather than none.
		if parse.ContainsPrivateKey(body) {
			return refuseOutbound()
		}
		return nil
	}
	if carriesKey("", doc) {
		return refuseOutbound()
	}
	return nil
}

func refuseOutbound() error {
	return fmt.Errorf("%w: this is an agent bug, please report it", ErrKeyMaterialOutbound)
}

// privateKeyArmor is the opening of a PEM private key in any of its forms
// ("RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", RFC
// 4716's "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"), in any case, with any
// spacing — Unicode spaces and format characters included — with Unicode
// dashes, and without needing the closing dashes, so a truncated armor line
// still counts. The same marker the server screens for (dtp-crypto's
// CertificateInput::PRIVATE_KEY_MARKER), so nothing it would call a key gets
// past here, and still nothing a path or an alias says by accident.
var privateKeyArmor = regexp.MustCompile(`(?i)[-\x{2010}-\x{2015}\x{2212}\x{FF0D}]{3,}` +
	keySpace + `*BEGIN[^\n]{0,80}?PRIVATE` + keySpace + `*[_-]?` + keySpace + `*KEY`)

const keySpace = `[\s\p{Z}\p{Cf}]`

func carriesKey(field string, v any) bool {
	switch v := v.(type) {
	case string:
		if strings.HasSuffix(field, "_pem") {
			return parse.ContainsPrivateKey([]byte(v))
		}
		return privateKeyArmor.MatchString(v)
	case map[string]any:
		for k, x := range v {
			if privateKeyArmor.MatchString(k) || carriesKey(k, x) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if carriesKey(field, x) {
				return true
			}
		}
	}
	return false
}
