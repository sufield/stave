package controldef

import (
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_UnknownCapabilityFailsLoud asserts the capability-containment
// invariant: a chain that references any capability outside the registered
// vocabulary must FAIL LOUD at validation — never silently no-op or skip — and,
// conversely, a chain whose capabilities are all registered must validate
// cleanly.
//
// Why a violation matters: the capability vocabulary is the closed contract
// between a chain and the catalog. If ValidateCapabilities silently accepted an
// unknown precondition/postcondition, a typo (or a capability the catalog never
// actually provides) would compose into a chain that can never fire — a control
// that looks active but is dead. Fail-loud here is what turns an authoring
// mistake into a build error instead of a silent coverage gap.
func TestProperty_UnknownCapabilityFailsLoud(t *testing.T) {
	known := []string{"cap.read", "cap.write", "cap.assume", "cap.exfil", "cap.persist"}
	registry := CapabilitySet{}
	for _, c := range known {
		registry[c] = struct{}{}
	}

	// drawCaps draws a capability list mixing registered names and arbitrary
	// (almost-certainly unknown) ones. Whether an entry is actually unknown is
	// decided by registry.IsValid below, so a coincidental collision is handled.
	drawCaps := func(rt *rapid.T, label string) []string {
		n := rapid.IntRange(0, 4).Draw(rt, label+"_count")
		out := make([]string, n)
		for i := range out {
			if rapid.Bool().Draw(rt, label+"_registered") {
				out[i] = known[rapid.IntRange(0, len(known)-1).Draw(rt, label+"_pick")]
			} else {
				out[i] = "unk." + rapid.StringMatching(`[a-z]{1,6}`).Draw(rt, label+"_name")
			}
		}
		return out
	}

	rapid.Check(t, func(rt *rapid.T) {
		pre := drawCaps(rt, "pre")
		post := drawCaps(rt, "post")
		chain := &ChainDefinition{ID: "chain.test", Preconditions: pre, Postconditions: post}

		referencesUnknown := false
		for _, c := range append(append([]string{}, pre...), post...) {
			if !registry.IsValid(c) {
				referencesUnknown = true
				break
			}
		}

		err := chain.ValidateCapabilities(registry)
		switch {
		case referencesUnknown && err == nil:
			rt.Fatalf("chain references an unknown capability but ValidateCapabilities returned nil "+
				"(silent no-op — a typo'd capability would compose into a dead control): pre=%v post=%v", pre, post)
		case !referencesUnknown && err != nil:
			rt.Fatalf("chain references only registered capabilities but ValidateCapabilities errored: %v "+
				"(pre=%v post=%v)", err, pre, post)
		}
	})
}
