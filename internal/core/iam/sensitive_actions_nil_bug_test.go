package iam

import (
	"testing"
)

func TestSensitiveActionRegistry_NilReceiver(t *testing.T) {
	var r *SensitiveActionRegistry

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("SensitiveActionRegistry method panicked on nil receiver: %v", rec)
		}
	}()

	cats := r.Classify("s3:GetObject")
	if len(cats) != 0 {
		t.Errorf("expected empty categories for nil registry, got %v", cats)
	}

	wildCats := r.ClassifyWildcard("s3:*")
	if len(wildCats) != 0 {
		t.Errorf("expected empty wildcard categories for nil registry, got %v", wildCats)
	}

	if r.HasDataAccess("s3:GetObject") {
		t.Errorf("expected HasDataAccess false for nil registry")
	}

	if r.HasCredentialExposure("iam:CreateAccessKey") {
		t.Errorf("expected HasCredentialExposure false for nil registry")
	}

	if r.HasPrivEsc("iam:PutRolePolicy") {
		t.Errorf("expected HasPrivEsc false for nil registry")
	}

	if count := r.CountByCategory([]string{"s3:GetObject"}, ActionDataAccess); count != 0 {
		t.Errorf("expected CountByCategory 0 for nil registry, got %d", count)
	}
}
