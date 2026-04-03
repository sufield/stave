package compliance

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestAccess011(t *testing.T) {
	inv := ControlRegistry.Lookup("ACCESS.011")
	if inv == nil {
		t.Fatal("ACCESS.011 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "no ListBucket — pass",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"}]
			}`)),
			wantPass: true,
		},
		{
			name: "public ListBucket — fail",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Principal":"*"}]
			}`)),
			wantPass: false,
		},
		{
			name: "ListBucket to specific principal — pass",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Principal":{"AWS":"arn:aws:iam::123456:root"}}]
			}`)),
			wantPass: true,
		},
		{
			name: "Deny ListBucket to wildcard — pass (Deny is safe)",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Principal":"*"}]
			}`)),
			wantPass: true,
		},
		{
			name: "ListBucket among multiple actions — fail",
			snap: snap(policyBucket("b", `{
				"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Principal":"*"}]
			}`)),
			wantPass: false,
		},
		{
			name:     "nil policy — pass",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: true,
		},
		{
			name:     "empty snapshot — pass",
			snap:     snap(),
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := inv.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v (finding: %s)", r.Pass, tc.wantPass, r.Finding)
			}
			if !tc.wantPass && !strings.Contains(r.Finding, "ListBucket") {
				t.Error("Finding should mention ListBucket")
			}
			if !tc.wantPass && !strings.Contains(r.Finding, "key enumeration") {
				t.Error("Finding should note key enumeration risk")
			}
		})
	}
}
