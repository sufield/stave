package translation

import (
	"strings"
	"testing"
)

func TestClassifyClause_Discriminator(t *testing.T) {
	for key := range discriminatorKeys {
		if got := ClassifyClause(key); got != RoleGate {
			t.Errorf("ClassifyClause(%q) = %v, want RoleGate (kind-discriminator)", key, got)
		}
	}
}

func TestClassifyClause_TopLevelKey(t *testing.T) {
	cases := []string{"protected_prefix", "exposure_source", "denied_service_wildcards"}
	for _, key := range cases {
		if got := ClassifyClause(key); got != RoleGate {
			t.Errorf("ClassifyClause(%q) = %v, want RoleGate (top-level key, parameterized)", key, got)
		}
	}
}

func TestClassifyClause_UnsafeMatch(t *testing.T) {
	cases := []string{
		"storage.access.public_read",
		"storage.access.public_write",
		"storage.controls.public_access_block.block_public_acls",
		"storage.object_ownership.rule",
		"storage.tags.data-classification",
		"identity.policies.has_admin_access",
	}
	for _, key := range cases {
		if got := ClassifyClause(key); got != RoleUnsafeMatch {
			t.Errorf("ClassifyClause(%q) = %v, want RoleUnsafeMatch", key, got)
		}
	}
}

func TestRenderClause_Eq(t *testing.T) {
	cases := []struct {
		name string
		c    Clause
		want string
	}{
		{
			name: "boolean unsafe-match (true)",
			c:    Clause{ObservationKey: "storage.access.public_read", Operator: "eq", ExpectedValue: true, ObservedValue: true},
			want: "the bucket allows anonymous read = true",
		},
		{
			name: "boolean unsafe-match (false)",
			c:    Clause{ObservationKey: "storage.controls.public_access_block.block_public_acls", Operator: "eq", ExpectedValue: false, ObservedValue: false},
			want: "BlockPublicAcls is enabled = false",
		},
		{
			name: "string gate",
			c:    Clause{ObservationKey: "storage.kind", Operator: "eq", ExpectedValue: "bucket", ObservedValue: "bucket"},
			want: "storage.kind = \"bucket\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RenderClause(tc.c, DefaultFieldRegistry)
			if got != tc.want {
				t.Errorf("RenderClause = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRenderClause_NoContradictionShape(t *testing.T) {
	// Regression coverage for the audit's sub-bug 1: rendering must
	// not produce "must equal X, but is X" anywhere.
	cases := []Clause{
		{ObservationKey: "storage.access.public_read", Operator: "eq", ExpectedValue: true, ObservedValue: true},
		{ObservationKey: "storage.controls.public_access_block.block_public_acls", Operator: "eq", ExpectedValue: false, ObservedValue: false},
		{ObservationKey: "storage.kind", Operator: "eq", ExpectedValue: "bucket", ObservedValue: "bucket"},
	}
	for _, c := range cases {
		got := RenderClause(c, DefaultFieldRegistry)
		if strings.Contains(got, "must equal") || strings.Contains(got, "but is") {
			t.Errorf("RenderClause(%+v) = %q — contradiction-shape wording leaked", c, got)
		}
	}
}

func TestRenderClause_Missing(t *testing.T) {
	c := Clause{ObservationKey: "storage.object_ownership.rule", Operator: "missing", ExpectedValue: true, ObservedValue: nil}
	got := RenderClause(c, DefaultFieldRegistry)
	want := "the Object Ownership rule is not set"
	if got != want {
		t.Errorf("RenderClause(missing) = %q, want %q", got, want)
	}
}

func TestRenderClause_Ne(t *testing.T) {
	c := Clause{ObservationKey: "storage.object_ownership.rule", Operator: "ne", ExpectedValue: "BucketOwnerEnforced", ObservedValue: nil}
	got := RenderClause(c, DefaultFieldRegistry)
	want := "the Object Ownership rule not equal \"BucketOwnerEnforced\" (observed: not set)"
	if got != want {
		t.Errorf("RenderClause(ne) = %q, want %q", got, want)
	}
}

func TestRenderClause_GenericOperator(t *testing.T) {
	c := Clause{ObservationKey: "storage.object_lock.retention_days", Operator: "gte", ExpectedValue: 365, ObservedValue: 30}
	got := RenderClause(c, DefaultFieldRegistry)
	if !strings.Contains(got, "(observed: 30)") {
		t.Errorf("RenderClause(gte) = %q, expected '(observed: 30)' suffix", got)
	}
	if !strings.Contains(got, "365") {
		t.Errorf("RenderClause(gte) = %q, expected expected-value 365", got)
	}
}

func TestOperatorProse_KnownOperators(t *testing.T) {
	tests := []struct {
		op   string
		want string
	}{
		{"eq", "equal"},
		{"ne", "not equal"},
		{"gt", "be greater than"},
		{"missing", "be missing"},
		{"present", "be set"},
		{"contains", "contain"},
	}
	for _, tc := range tests {
		got := OperatorProse(tc.op)
		if got != tc.want {
			t.Errorf("OperatorProse(%q) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestOperatorProse_UnknownFallback(t *testing.T) {
	got := OperatorProse("unknown_op")
	if got != "unknown_op" {
		t.Errorf("OperatorProse(unknown) = %q, want raw op name", got)
	}
}
