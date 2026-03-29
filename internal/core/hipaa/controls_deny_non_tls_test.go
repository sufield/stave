package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestControls004(t *testing.T) {
	inv := ControlRegistry.Lookup("CONTROLS.004")
	if inv == nil {
		t.Fatal("CONTROLS.004 not registered")
	}

	denyNonTLSPolicy := `{
		"Statement":[{
			"Effect":"Deny",
			"Principal":"*",
			"Action":"s3:*",
			"Resource":"arn:aws:s3:::b/*",
			"Condition":{"Bool":{"aws:SecureTransport":"false"}}
		}]
	}`

	allowOnlyPolicy := `{
		"Statement":[{
			"Effect":"Allow",
			"Principal":"*",
			"Action":"s3:GetObject",
			"Resource":"arn:aws:s3:::b/*"
		}]
	}`

	denyWithBoolFalse := `{
		"Statement":[{
			"Effect":"Deny",
			"Principal":"*",
			"Action":"s3:*",
			"Resource":"arn:aws:s3:::b/*",
			"Condition":{"Bool":{"aws:SecureTransport":false}}
		}]
	}`

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name:     "deny non-TLS present — pass",
			snap:     snap(policyBucket("b", denyNonTLSPolicy)),
			wantPass: true,
		},
		{
			name:     "deny non-TLS with bool false — pass",
			snap:     snap(policyBucket("b", denyWithBoolFalse)),
			wantPass: true,
		},
		{
			name:     "only Allow statements — fail",
			snap:     snap(policyBucket("b", allowOnlyPolicy)),
			wantPass: false,
		},
		{
			name:     "no policy — fail",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: false,
		},
		{
			name:     "empty policy — fail",
			snap:     snap(policyBucket("b", "")),
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
		})
	}
}
