package sirfacts

import (
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

// Tests for purposeFlagFacts — the semicolon-delimited key=value
// parser that closes the substring-extraction gap surfaced by the
// s3-tenant-prefix-isolation fixture (see SMT-QUERY-GAPS.md).
//
// These tests exercise the parser against AssetFact properties.
// Note: the same gap on the identity side (where the
// s3-tenant-prefix-isolation `purpose` actually lives) needs a
// wider SIR-boundary change (carry Properties on IdentityFact)
// which is out of scope for this projector — see the package
// docstring on purposeFlagFacts.

func TestPurposeFlagFacts_ParsesSemicolonKV(t *testing.T) {
	assets := []sir.AssetFact{{
		ID:   "signer-1",
		Type: "app_signer",
		Properties: map[string]any{
			"purpose": "signs_uploads;enforce_prefix=false;allow_traversal=true",
		},
	}}
	facts := purposeFlagFacts(assets, nil)
	got := factsToMap(facts)
	wantPairs := []string{"enforce_prefix=false", "allow_traversal=true"}
	for _, want := range wantPairs {
		if !hasFact(got, "signer-1", "has_purpose_flag", want) {
			t.Errorf("missing has_purpose_flag(signer-1, %q); got: %v", want, got["signer-1"])
		}
	}
	// "signs_uploads" is a bare tag, not a k=v pair — must be
	// silently skipped, NOT emitted with an empty value (which
	// would conflate the tag-and-pair concerns the schema rule
	// in purposeFlagFacts' docstring explicitly separates).
	for _, f := range facts {
		if f.Object == "signs_uploads=" || f.Object == "signs_uploads" {
			t.Errorf("bare tag %q must not produce a fact", f.Object)
		}
	}
}

func TestPurposeFlagFacts_SkipsAssetsWithoutPurpose(t *testing.T) {
	assets := []sir.AssetFact{{
		ID:         "bucket-1",
		Type:       "aws_s3_bucket",
		Properties: map[string]any{"storage": map[string]any{"kind": "bucket"}},
	}}
	if facts := purposeFlagFacts(assets, nil); len(facts) != 0 {
		t.Errorf("expected 0 facts on asset without purpose, got %d", len(facts))
	}
}

func TestPurposeFlagFacts_HandlesWhitespace(t *testing.T) {
	assets := []sir.AssetFact{{
		ID:   "signer-2",
		Type: "app_signer",
		Properties: map[string]any{
			"purpose": "  signs_uploads ; enforce_prefix = true ;  allow_traversal=false  ",
		},
	}}
	got := factsToMap(purposeFlagFacts(assets, nil))
	if !hasFact(got, "signer-2", "has_purpose_flag", "enforce_prefix=true") {
		t.Errorf("trimmed enforce_prefix=true missing; got: %v", got["signer-2"])
	}
	if !hasFact(got, "signer-2", "has_purpose_flag", "allow_traversal=false") {
		t.Errorf("trimmed allow_traversal=false missing; got: %v", got["signer-2"])
	}
}

func TestPurposeFlagFacts_LowercasesKeyHalfOnly(t *testing.T) {
	// Keys are normalised to lowercase so authors can grep without
	// case-juggling; values stay verbatim because they're often
	// resource identifiers / ARNs / enum strings that downstream
	// queries match exactly.
	assets := []sir.AssetFact{{
		ID:   "signer-3",
		Type: "app_signer",
		Properties: map[string]any{
			"purpose": "Enforce_Prefix=TRUE;Mode=ReadWrite",
		},
	}}
	got := factsToMap(purposeFlagFacts(assets, nil))
	if !hasFact(got, "signer-3", "has_purpose_flag", "enforce_prefix=TRUE") {
		t.Errorf("key half should be lowercased, value half preserved; got: %v", got["signer-3"])
	}
	if !hasFact(got, "signer-3", "has_purpose_flag", "mode=ReadWrite") {
		t.Errorf("ReadWrite value should be preserved verbatim; got: %v", got["signer-3"])
	}
}

func TestPurposeFlagFacts_WalksIdentitiesToo(t *testing.T) {
	// IdentityFact.Properties is the SIR-boundary addition that
	// makes s3-tenant-prefix-isolation's `purpose` field reachable
	// from the solver side. Without this loop the identity's
	// enforce_prefix=true|false discriminator stays invisible —
	// the asset-side bucket has no purpose field.
	identities := []sir.IdentityFact{{
		PrincipalID: "appsigner:s3:acme-uploads",
		Properties: map[string]any{
			"purpose": "signs_uploads;enforce_prefix=false;allow_traversal=true",
		},
	}}
	facts := purposeFlagFacts(nil, identities)
	got := factsToMap(facts)
	if !hasFact(got, "appsigner:s3:acme-uploads", "has_purpose_flag", "enforce_prefix=false") {
		t.Errorf("identity-side enforce_prefix=false missing; got: %v", got)
	}
	if !hasFact(got, "appsigner:s3:acme-uploads", "has_purpose_flag", "allow_traversal=true") {
		t.Errorf("identity-side allow_traversal=true missing; got: %v", got)
	}
	// Evidence path must root at identities[N] so trace-back
	// distinguishes asset-side and identity-side facts.
	for _, f := range facts {
		if !strings.HasPrefix(f.Evidence, "identities[") {
			t.Errorf("identity fact's Evidence should root at identities[]; got %q", f.Evidence)
		}
	}
}

func TestPurposeFlagFacts_SkipsEmptyAndMalformed(t *testing.T) {
	assets := []sir.AssetFact{{
		ID:   "signer-4",
		Type: "app_signer",
		Properties: map[string]any{
			"purpose": ";;=value-without-key;valid=ok;;",
		},
	}}
	got := factsToMap(purposeFlagFacts(assets, nil))
	// "valid=ok" is the only well-formed pair; the rest must be
	// silently skipped (empty token, empty key).
	if !hasFact(got, "signer-4", "has_purpose_flag", "valid=ok") {
		t.Errorf("valid pair missing; got: %v", got["signer-4"])
	}
	if len(got["signer-4"]) != 1 {
		t.Errorf("expected 1 fact, got %d: %v", len(got["signer-4"]), got["signer-4"])
	}
}

// helpers

// factsToMap groups facts by subject -> list of "predicate=object"
// for easy assertion lookup.
func factsToMap(facts []Fact) map[string][]string {
	out := map[string][]string{}
	for _, f := range facts {
		out[f.Subject] = append(out[f.Subject], f.Predicate+"="+f.Object)
	}
	return out
}

func hasFact(m map[string][]string, subject, predicate, object string) bool {
	want := predicate + "=" + object
	return slices.Contains(m[subject], want)
}
