package hipaa

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func policyBucket(id, policyJSON string) asset.Asset {
	return s3Bucket(id, map[string]any{"policy_json": policyJSON})
}

func TestAccess002(t *testing.T) {
	inv := AccessRegistry.Lookup("ACCESS.002")
	if inv == nil {
		t.Fatal("ACCESS.002 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "no wildcard actions — pass",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"}]
			}`)),
			wantPass: true,
		},
		{
			name: "s3:* wildcard — fail",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"s3:*","Principal":"*"}]
			}`)),
			wantPass: false,
		},
		{
			name: "full wildcard * — fail",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"*","Principal":"*"}]
			}`)),
			wantPass: false,
		},
		{
			name: "Deny with wildcard — pass (Deny is safe)",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Deny","Action":"s3:*","Principal":"*"}]
			}`)),
			wantPass: true,
		},
		{
			name:     "nil policy — pass",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: true,
		},
		{
			name:     "empty policy string — pass",
			snap:     snap(policyBucket("b", "")),
			wantPass: true,
		},
		{
			name:     "empty snapshot — pass",
			snap:     snap(),
			wantPass: true,
		},
		{
			name: "multiple statements, second has wildcard — fail",
			snap: snap(policyBucket("b", `{
				"Statement":[
					{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"},
					{"Sid":"bad","Effect":"Allow","Action":"s3:*","Principal":"*"}
				]
			}`)),
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := inv.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v (finding: %s)", r.Pass, tc.wantPass, r.Finding)
			}
			if !tc.wantPass && !strings.Contains(r.Remediation, "s3:GetObject") {
				t.Error("Remediation should include minimum action set")
			}
		})
	}
}
