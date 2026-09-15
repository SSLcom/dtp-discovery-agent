package transport

import (
	"errors"
	"fmt"

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
func guardOutbound(body []byte) error {
	if parse.ContainsPrivateKey(body) {
		return fmt.Errorf("%w: this is an agent bug, please report it", ErrKeyMaterialOutbound)
	}
	return nil
}
