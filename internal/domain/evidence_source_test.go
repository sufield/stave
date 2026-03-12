package domain

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/domain/asset"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/engine"
)

func TestExtractSourceEvidenceUsesCanonicalPath(t *testing.T) {
	resource := asset.Asset{
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"policy_public_statements": []string{"B", "A"},
				"acl_public_grantees":      []string{"acl-b", "acl-a"},
			},
			"vendor": map[string]any{
				"aws": map[string]any{
					"s3": map[string]any{
						"policy_public_statements": []string{"vendor-specific"},
					},
				},
			},
		},
	}

	got := engine.ExtractSourceEvidence(resource, []evaluation.RootCause{evaluation.RootCauseIdentity, evaluation.RootCauseResource})
	if got == nil {
		t.Fatal("expected source evidence")
	}
	if !reflect.DeepEqual(got.IdentityStatements, []string{"A", "B"}) {
		t.Fatalf("unexpected policy statements: %v", got.IdentityStatements)
	}
	if !reflect.DeepEqual(got.ResourceGrantees, []string{"acl-a", "acl-b"}) {
		t.Fatalf("unexpected acl grantees: %v", got.ResourceGrantees)
	}
}

func TestExtractSourceEvidenceReturnsNilForTopLevelOnlyFields(t *testing.T) {
	resource := asset.Asset{
		Properties: map[string]any{
			"policy_public_statements": []string{"top-level-a"},
			"acl_public_grantees":      []string{"top-level-b"},
		},
	}

	got := engine.ExtractSourceEvidence(resource, []evaluation.RootCause{evaluation.RootCauseIdentity, evaluation.RootCauseResource})
	if got != nil {
		t.Fatalf("expected nil source evidence for top-level-only fields, got %+v", got)
	}
}

func TestExtractSourceEvidenceRespectsRootCauseFilter(t *testing.T) {
	resource := asset.Asset{
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"policy_public_statements": []string{"stmt"},
				"acl_public_grantees":      []string{"acl"},
			},
		},
	}

	got := engine.ExtractSourceEvidence(resource, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if got == nil {
		t.Fatal("expected source evidence")
	}
	if !reflect.DeepEqual(got.IdentityStatements, []string{"stmt"}) {
		t.Fatalf("unexpected policy statements: %v", got.IdentityStatements)
	}
	if len(got.ResourceGrantees) != 0 {
		t.Fatalf("expected no acl grantees, got %v", got.ResourceGrantees)
	}
}
