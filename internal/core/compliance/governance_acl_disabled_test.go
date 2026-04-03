package compliance

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func ownershipBucket(id, ownership string) asset.Asset {
	return s3Bucket(id, map[string]any{
		"storage": map[string]any{"ownership_controls": ownership},
	})
}

func TestGovernance001(t *testing.T) {
	inv := ControlRegistry.Lookup("GOVERNANCE.001")
	if inv == nil {
		t.Fatal("GOVERNANCE.001 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name:     "BucketOwnerEnforced — pass",
			snap:     snap(ownershipBucket("b", "BucketOwnerEnforced")),
			wantPass: true,
		},
		{
			name:     "BucketOwnerPreferred — fail",
			snap:     snap(ownershipBucket("b", "BucketOwnerPreferred")),
			wantPass: false,
		},
		{
			name:     "ObjectWriter — fail",
			snap:     snap(ownershipBucket("b", "ObjectWriter")),
			wantPass: false,
		},
		{
			name:     "empty ownership — fail",
			snap:     snap(ownershipBucket("b", "")),
			wantPass: false,
		},
		{
			name:     "no storage properties — fail",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: false,
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
			if !tc.wantPass && !strings.Contains(r.Remediation, "AWS Backup") {
				t.Error("Remediation should mention AWS Backup exception")
			}
		})
	}
}
