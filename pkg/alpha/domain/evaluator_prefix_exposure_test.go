package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/engine"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/exposure"
)

// newPrefixSet is a test helper wrapping NewPrefixSetFromPrefixes with raw strings.
func newPrefixSet(raw []string) policy.PrefixSet {
	prefixes := make([]kernel.ObjectPrefix, len(raw))
	for i, s := range raw {
		prefixes[i] = kernel.ObjectPrefix(s)
	}
	return policy.NewPrefixSetFromPrefixes(prefixes)
}

func TestNewPrefixSet(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []kernel.ObjectPrefix
	}{
		{"nil input", nil, nil},
		{"empty slice", []string{}, nil},
		{"already normalized", []string{"images/", "docs/"}, []kernel.ObjectPrefix{"docs/", "images/"}},
		{"missing trailing slash", []string{"images", "docs"}, []kernel.ObjectPrefix{"docs/", "images/"}},
		{"mixed", []string{"images/", "docs"}, []kernel.ObjectPrefix{"docs/", "images/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := newPrefixSet(tt.input)
			got := ps.Prefixes()
			if len(got) != len(tt.expect) {
				t.Fatalf("len=%d, want %d", len(got), len(tt.expect))
			}
			for i := range got {
				if got[i] != tt.expect[i] {
					t.Errorf("[%d]=%q, want %q", i, got[i], tt.expect[i])
				}
			}
			wantEmpty := len(tt.expect) == 0
			if ps.Empty() != wantEmpty {
				t.Errorf("Empty()=%v, want %v", ps.Empty(), wantEmpty)
			}
		})
	}
}

func TestDetectOverlap(t *testing.T) {
	tests := []struct {
		name      string
		allowed   []string
		protected []string
		wantA     kernel.ObjectPrefix
		wantP     kernel.ObjectPrefix
	}{
		{name: "no overlap", allowed: []string{"images/"}, protected: []string{"invoices/"}},
		{name: "protected inside allowed", allowed: []string{"data/"}, protected: []string{"data/secrets/"}, wantA: "data/", wantP: "data/secrets/"},
		{name: "allowed inside protected", allowed: []string{"data/public/"}, protected: []string{"data/"}, wantA: "data/public/", wantP: "data/"},
		{name: "exact match", allowed: []string{"shared/"}, protected: []string{"shared/"}, wantA: "shared/", wantP: "shared/"},
		{name: "no overlap multiple", allowed: []string{"images/", "static/"}, protected: []string{"invoices/", "secrets/"}},
		{name: "same-set element between cross-set pair", allowed: []string{"a/", "a/w/"}, protected: []string{"a/x/"}, wantA: "a/", wantP: "a/x/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflict := policy.DetectOverlap(newPrefixSet(tt.allowed), newPrefixSet(tt.protected))
			wantConflict := tt.wantA != "" || tt.wantP != ""
			if wantConflict {
				if conflict == nil {
					t.Fatal("expected conflict, got nil")
				}
				if conflict.Allowed != tt.wantA {
					t.Errorf("Allowed=%q, want %q", conflict.Allowed, tt.wantA)
				}
				if conflict.Protected != tt.wantP {
					t.Errorf("Protected=%q, want %q", conflict.Protected, tt.wantP)
				}
			} else {
				if conflict != nil {
					t.Fatalf("expected no conflict, got Allowed=%q Protected=%q", conflict.Allowed, conflict.Protected)
				}
			}
		})
	}
}

func TestCheckExposure(t *testing.T) {
	tests := []struct {
		name     string
		prefix   kernel.ObjectPrefix
		facts    exposure.Facts
		wantPub  bool
		wantEvid string
	}{
		{
			name:   "identity grants public read",
			prefix: "invoices/",
			facts: exposure.Facts{
				HasIdentityEvidence: true,
				IdentityGrants:      exposure.Grants{{Scope: kernel.ObjectPrefix("invoices/"), SourceID: "AllowPublic"}},
			},
			wantPub:  true,
			wantEvid: "identity:AllowPublic",
		},
		{
			name:   "identity blocked",
			prefix: "invoices/",
			facts: exposure.Facts{
				HasIdentityEvidence: true,
				IdentityGrants:      exposure.Grants{{Scope: kernel.WildcardPrefix}},
				IdentityReadBlocked: true,
			},
			wantPub: false,
		},
		{
			name:   "resource grants public read",
			prefix: "invoices/",
			facts: exposure.Facts{
				HasResourceEvidence: true,
				ResourceReadAll:     true,
			},
			wantPub:  true,
			wantEvid: "resource",
		},
		{
			name:   "resource blocked",
			prefix: "invoices/",
			facts: exposure.Facts{
				HasResourceEvidence: true,
				ResourceReadAll:     true,
				ResourceReadBlocked: true,
			},
			wantPub: false,
		},
		{
			name:     "missing evidence fail-closed",
			prefix:   "invoices/",
			facts:    exposure.Facts{},
			wantPub:  true,
			wantEvid: "missing_evidence",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.facts.CheckExposure(tt.prefix)
			if result.Exposed != tt.wantPub {
				t.Errorf("Exposed=%v, want %v", result.Exposed, tt.wantPub)
			}
			if got := result.String(); got != tt.wantEvid {
				t.Errorf("evidence=%q, want %q", got, tt.wantEvid)
			}
		})
	}
}

func TestGrantEvidence(t *testing.T) {
	tests := []struct {
		name string
		g    exposure.Grant
		want string
	}{
		{
			name: "with statement ID",
			g:    exposure.Grant{Scope: kernel.WildcardPrefix, SourceID: "AllowPublic"},
			want: "identity:AllowPublic",
		},
		{
			name: "without statement ID",
			g:    exposure.Grant{Scope: kernel.WildcardPrefix, SourceID: ""},
			want: "identity",
		},
		{
			name: "whitespace-only statement ID",
			g:    exposure.Grant{Scope: kernel.WildcardPrefix, SourceID: "   "},
			want: "identity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.g.Evidence().String()
			if got != tt.want {
				t.Errorf("evidence()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestEvaluatePrefixExposureForRow(t *testing.T) {
	now := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	makeInv := func(allowed, protected []string) *policy.ControlDefinition {
		params := policy.NewParams(map[string]any{
			"allowed_public_prefixes": toInterfaceSlice(allowed),
			"protected_prefixes":      toInterfaceSlice(protected),
		})
		ctl := &policy.ControlDefinition{
			ID:          "CTL.EXP.VISIBILITY.003",
			Name:        "Public Read Allowed Only for Approved Prefixes",
			Description: "Test control",
			Type:        policy.TypePrefixExposure,
			Params:      params,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")}},
			},
		}
		_ = ctl.Prepare()
		return ctl
	}

	makeTimeline := func(storage map[string]any) *asset.Timeline {
		resource := asset.Asset{
			ID:     "res:aws:s3:bucket:example-bucket",
			Type:   kernel.AssetType("storage_bucket"),
			Vendor: kernel.Vendor("aws"),
			Properties: map[string]any{
				"storage": storage,
			},
		}
		timeline, err := asset.NewTimeline(resource)
		if err != nil {
			t.Fatal(err)
		}
		if err := timeline.RecordObservation(now, true); err != nil {
			t.Fatal(err)
		}
		return timeline
	}

	t.Run("safe - only approved prefix is public", func(t *testing.T) {
		ctl := makeInv([]string{"images/"}, []string{"invoices/"})
		timeline := makeTimeline(map[string]any{
			"kind": "bucket",
			"name": "example-bucket",
			"prefix_exposure": map[string]any{
				"has_identity_evidence":    true,
				"has_resource_evidence":    true,
				"identity_read_scopes":     []any{"images/"},
				"identity_source_by_scope": map[string]any{"images/": "AllowPublicImages"},
				"identity_read_blocked":    false,
				"resource_read_all":        false,
				"resource_read_blocked":    false,
			},
		})

		policyInv := *ctl
		row, findings := engine.EvaluatePrefixExposureForRow(timeline, &policyInv, now)

		if row.Decision != evaluation.DecisionPass {
			t.Errorf("decision=%s, want PASS", row.Decision)
		}
		if len(findings) != 0 {
			t.Errorf("findings=%d, want 0", len(findings))
		}
	})

	t.Run("unsafe - bucket-wide policy", func(t *testing.T) {
		ctl := makeInv([]string{"images/"}, []string{"invoices/"})
		timeline := makeTimeline(map[string]any{
			"kind": "bucket",
			"name": "example-bucket",
			"prefix_exposure": map[string]any{
				"has_identity_evidence":    true,
				"has_resource_evidence":    true,
				"identity_read_scopes":     []any{"*"},
				"identity_source_by_scope": map[string]any{"*": "AllowAll"},
				"identity_read_blocked":    false,
				"resource_read_all":        false,
				"resource_read_blocked":    false,
			},
		})

		policyInv := *ctl
		row, findings := engine.EvaluatePrefixExposureForRow(timeline, &policyInv, now)

		if row.Decision != evaluation.DecisionViolation {
			t.Errorf("decision=%s, want VIOLATION", row.Decision)
		}
		if len(findings) != 1 {
			t.Fatalf("findings=%d, want 1", len(findings))
		}
		if v := findMisconfiguration(findings[0].Evidence.Misconfigurations); v != "identity:AllowAll" {
			t.Errorf("exposure_source=%v, want policy:AllowAll", v)
		}
	})

	t.Run("unsafe - config overlap", func(t *testing.T) {
		ctl := makeInv([]string{"data/"}, []string{"data/secrets/"})
		timeline := makeTimeline(map[string]any{"kind": "bucket", "name": "example-bucket"})

		policyInv := *ctl
		row, findings := engine.EvaluatePrefixExposureForRow(timeline, &policyInv, now)

		if row.Decision != evaluation.DecisionViolation {
			t.Errorf("decision=%s, want VIOLATION", row.Decision)
		}
		if len(findings) != 1 {
			t.Fatalf("findings=%d, want 1", len(findings))
		}
		if v := findMisconfiguration(findings[0].Evidence.Misconfigurations); v != "config_overlap" {
			t.Errorf("exposure_source=%v, want config_overlap", v)
		}
	})

	t.Run("unsafe - missing evidence", func(t *testing.T) {
		ctl := makeInv([]string{"images/"}, []string{"invoices/"})
		timeline := makeTimeline(map[string]any{"kind": "bucket", "name": "example-bucket"})

		policyInv := *ctl
		row, findings := engine.EvaluatePrefixExposureForRow(timeline, &policyInv, now)

		if row.Decision != evaluation.DecisionViolation {
			t.Errorf("decision=%s, want VIOLATION", row.Decision)
		}
		if len(findings) != 1 {
			t.Fatalf("findings=%d, want 1", len(findings))
		}
		if v := findMisconfiguration(findings[0].Evidence.Misconfigurations); v != "missing_evidence" {
			t.Errorf("exposure_source=%v, want missing_evidence", v)
		}
	})

	t.Run("no protected prefixes configured", func(t *testing.T) {
		ctl := makeInv([]string{"images/"}, nil)
		timeline := makeTimeline(map[string]any{"kind": "bucket", "name": "example-bucket"})

		policyInv := *ctl
		row, findings := engine.EvaluatePrefixExposureForRow(timeline, &policyInv, now)

		if row.Decision != evaluation.DecisionViolation {
			t.Errorf("decision=%s, want VIOLATION", row.Decision)
		}
		if len(findings) != 1 {
			t.Fatalf("findings=%d, want 1", len(findings))
		}
		if v := findMisconfiguration(findings[0].Evidence.Misconfigurations); v != "not_configured" {
			t.Errorf("exposure_source=%v, want not_configured", v)
		}
	})
}

func findMisconfiguration(misconfigs []policy.Misconfiguration) any {
	for _, mc := range misconfigs {
		if mc.Property == "exposure_source" {
			return mc.ActualValue
		}
	}
	return nil
}

func toInterfaceSlice(s []string) []any {
	if s == nil {
		return nil
	}
	result := make([]any, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}
