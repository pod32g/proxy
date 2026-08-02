package proxy

import (
	"testing"

	"github.com/pod32g/proxy/internal/header"
)

// The relationship between the two lists, asserted rather than trusted.
//
// removeHopByHop strips these headers because forwarding them breaks RFC 7230
// §6.1 and, for Proxy-Authorization, hands every origin the credentials a
// client used on this proxy. header.forbidden refuses to let a rule set them,
// which is the other half of the same decision — a rule that could re-add one
// would bring both problems straight back.
//
// They are separate lists for a real reason: header.forbidden also covers
// Content-Length, which the transport owns and which is not hop-by-hop. So they
// cannot simply be merged. What they can be is checked, which is the difference
// between an invariant and a coincidence. Two other pairs of hand-synchronised
// lists in this repo had already drifted before anyone looked.
//
// This test lives in the proxy package because header cannot import it.
func TestEveryStrippedHeaderIsForbiddenToRules(t *testing.T) {
	if len(hopByHopHeaders) == 0 {
		t.Fatal("no hop-by-hop headers; this test would assert nothing")
	}
	for _, name := range hopByHopHeaders {
		if _, blocked := header.Forbidden(name); !blocked {
			t.Errorf("%s is stripped as hop-by-hop but a header rule may set it: "+
				"add it to the forbidden map in internal/header, or a rule can "+
				"put back exactly what removeHopByHop exists to remove", name)
		}
	}
}
