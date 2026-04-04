package compliance

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestAccess009(t *testing.T) {
	ctl := ControlRegistry.Lookup("ACCESS.009")
	if ctl == nil {
		t.Fatal("ACCESS.009 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "policy with Deny NumericGreaterThan s3:signatureAge — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"policy_json": `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "DenyOldPresignedURLs",
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:*",
							"Resource": "arn:aws:s3:::test-bucket/*",
							"Condition": {
								"NumericGreaterThan": {
									"s3:signatureAge": 600000
								}
							}
						}
					]
				}`,
			})),
			wantPass: true,
		},
		{
			name: "policy with Deny StringNotEquals s3:authType REST-HEADER — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"policy_json": `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "DenyNonHeaderAuth",
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::test-bucket/*",
							"Condition": {
								"StringNotEquals": {
									"s3:authType": "REST-HEADER"
								}
							}
						}
					]
				}`,
			})),
			wantPass: true,
		},
		{
			name: "policy exists but no presigned URL conditions — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"policy_json": `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "AllowGetObject",
							"Effect": "Allow",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::test-bucket/*"
						}
					]
				}`,
			})),
			wantPass: false,
		},
		{
			name:     "no policy_json at all — fail",
			snap:     snap(s3Bucket("test-bucket", map[string]any{})),
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
			r := ctl.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v (finding: %s)", r.Pass, tc.wantPass, r.Finding)
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
