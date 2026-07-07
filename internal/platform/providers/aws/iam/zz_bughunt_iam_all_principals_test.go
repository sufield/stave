package iam

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_ResolveAllPrincipals_IncludesAssetFallbackRoles(t *testing.T) {
	// Create an asset representing an IAM role
	ast := asset.Asset{
		ID:     "arn:aws:iam::123456789012:role/AssetRole",
		Type:   kernel.AssetType("aws_iam_role"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"identity": map[string]any{
				"policies_json": `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*"
						}
					]
				}`,
				"scp_json": `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*"
						}
					]
				}`,
			},
		},
	}

	snap := &asset.Snapshot{
		SchemaVersion: "1",
		CapturedAt:    time.Now(),
		Source:        "test",
		Assets:        []asset.Asset{ast},
	}

	resolved, _ := ResolveAllPrincipals(snap)

	// Under the buggy code: ResolveAllPrincipals only loops over snap.Identities.
	// So resolved will not contain "arn:aws:iam::123456789012:role/AssetRole".
	if _, ok := resolved["arn:aws:iam::123456789012:role/AssetRole"]; !ok {
		t.Errorf("expected ResolveAllPrincipals to include IAM roles fallback-defined in snap.Assets, but it did not")
	}
}
