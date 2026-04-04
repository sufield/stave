package compliance

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func s3Bucket(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.NewAssetType("aws_s3_bucket"),
		Vendor:     "aws",
		Properties: props,
	}
}

func snap(assets ...asset.Asset) asset.Snapshot {
	return asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		CapturedAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets:        assets,
	}
}

func bpaProps(blockACLs, ignoreACLs, blockPolicy, restrictBuckets bool) map[string]any {
	return map[string]any{
		"storage": map[string]any{
			"controls": map[string]any{
				"public_access_block": map[string]any{
					"block_public_acls":       blockACLs,
					"ignore_public_acls":      ignoreACLs,
					"block_public_policy":     blockPolicy,
					"restrict_public_buckets": restrictBuckets,
				},
			},
		},
	}
}

func TestAccess001(t *testing.T) {
	ctl := ControlRegistry.Lookup("ACCESS.001")
	if ctl == nil {
		t.Fatal("ACCESS.001 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
		wantSev  policy.Severity
	}{
		{
			name:     "all BPA enabled",
			snap:     snap(s3Bucket("bucket-a", bpaProps(true, true, true, true))),
			wantPass: true,
		},
		{
			name:     "BPA partially enabled",
			snap:     snap(s3Bucket("bucket-a", bpaProps(true, false, true, false))),
			wantPass: false,
			wantSev:  policy.SeverityCritical,
		},
		{
			name:     "BPA all disabled",
			snap:     snap(s3Bucket("bucket-a", bpaProps(false, false, false, false))),
			wantPass: false,
			wantSev:  policy.SeverityCritical,
		},
		{
			name:     "no BPA properties at all",
			snap:     snap(s3Bucket("bucket-a", map[string]any{})),
			wantPass: false,
			wantSev:  policy.SeverityCritical,
		},
		{
			name: "account-level BPA active, bucket-level missing",
			snap: snap(s3Bucket("bucket-a", map[string]any{
				"storage": map[string]any{
					"controls": map[string]any{
						"account_public_access_fully_blocked": true,
					},
				},
			})),
			wantPass: false,
			wantSev:  policy.SeverityLow,
		},
		{
			name:     "empty snapshot",
			snap:     snap(),
			wantPass: true,
		},
		{
			name: "non-S3 asset ignored",
			snap: snap(asset.Asset{
				ID:   "some-rds",
				Type: kernel.NewAssetType("aws_rds_instance"),
			}),
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := ctl.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v", r.Pass, tc.wantPass)
			}
			if !tc.wantPass && r.Severity != tc.wantSev {
				t.Errorf("Severity: got %s, want %s", r.Severity, tc.wantSev)
			}
			if !tc.wantPass && r.Finding == "" {
				t.Error("Finding should not be empty on failure")
			}
			if !tc.wantPass && r.Remediation == "" {
				t.Error("Remediation should not be empty on failure")
			}
		})
	}
}
