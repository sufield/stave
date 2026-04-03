package compliance

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestControls001Strict(t *testing.T) {
	inv := ControlRegistry.Lookup("CONTROLS.001.STRICT")
	if inv == nil {
		t.Fatal("CONTROLS.001.STRICT not registered")
	}

	tests := []struct {
		name        string
		snap        asset.Snapshot
		wantPass    bool
		findingLike string // substring to check in finding
	}{
		{
			name:     "SSE-KMS with CMK — pass",
			snap:     snap(encBucket("b", true, "aws:kms", "arn:aws:kms:us-east-1:123:key/abc-123")),
			wantPass: true,
		},
		{
			name:        "SSE-KMS with AWS-managed key alias — fail",
			snap:        snap(encBucket("b", true, "aws:kms", "alias/aws/s3")),
			wantPass:    false,
			findingLike: "cannot be revoked",
		},
		{
			name:        "SSE-S3 (AES256) — fail",
			snap:        snap(encBucket("b", true, "AES256", "")),
			wantPass:    false,
			findingLike: "not aws:kms",
		},
		{
			name:        "SSE-KMS but no key ID — fail",
			snap:        snap(encBucket("b", true, "aws:kms", "")),
			wantPass:    false,
			findingLike: "no KMS key ID",
		},
		{
			name:        "encryption disabled — fail",
			snap:        snap(encBucket("b", false, "", "")),
			wantPass:    false,
			findingLike: "not enabled",
		},
		{
			name:        "no encryption properties — fail",
			snap:        snap(s3Bucket("b", map[string]any{})),
			wantPass:    false,
			findingLike: "not enabled",
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
			if !tc.wantPass && tc.findingLike != "" && !strings.Contains(r.Finding, tc.findingLike) {
				t.Errorf("Finding should contain %q, got: %s", tc.findingLike, r.Finding)
			}
			if r.Pass == false && r.Severity != Critical {
				t.Errorf("Severity: got %s, want CRITICAL", r.Severity)
			}
		})
	}
}

func TestControls001Strict_RegisteredSeparately(t *testing.T) {
	base := ControlRegistry.Lookup("CONTROLS.001")
	strict := ControlRegistry.Lookup("CONTROLS.001.STRICT")

	if base == nil || strict == nil {
		t.Fatal("both CONTROLS.001 and CONTROLS.001.STRICT must be registered")
	}
	if base.Def().ID() == strict.Def().ID() {
		t.Error("CONTROLS.001 and CONTROLS.001.STRICT must have different IDs")
	}
}
