package main

import (
	"strings"
	"testing"
)

// PROXY-102. Every flag carries a recorded decision, so the next person to ask
// whether the surface should shrink reads the reasoning rather than deriving it
// again — and a flag added later cannot slip in unclassified, which is exactly
// how nine settings drifted out of the config file (PROXY-100).
func TestEveryFlagIsClassified(t *testing.T) {
	flags := declaredFlags(t)
	if len(flags) < 40 {
		t.Fatalf("found only %d flags; the parse is wrong, not the code", len(flags))
	}
	for _, f := range flags {
		if f == "help" {
			continue
		}
		key := strings.ReplaceAll(f, "-", "")
		d, ok := flagDecisions[key]
		if !ok {
			t.Errorf("-%s has no entry in flagDecisions: decide whether it stays, "+
				"and record why", f)
			continue
		}
		if d.why == "" {
			t.Errorf("-%s is classified with no reason", f)
		}
		// The two lists have to agree: a flag marked keep here but listed in
		// `deprecated` would warn while claiming to be permanent.
		_, isDeprecated := deprecated[f]
		if d.keep == isDeprecated {
			t.Errorf("-%s: flagDecisions says keep=%v but deprecated=%v", f, d.keep, isDeprecated)
		}
	}
	// And no stale entries naming flags that no longer exist.
	for key := range flagDecisions {
		found := false
		for _, f := range flags {
			if strings.ReplaceAll(f, "-", "") == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("flagDecisions has %q, which is not a flag any more", key)
		}
	}
}
