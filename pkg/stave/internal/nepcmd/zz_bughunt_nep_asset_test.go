package nepcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_ResolvePrincipal_FallbackAssetPolicies(t *testing.T) {
	// Create an asset representing an IAM role with admin policy.
	adminPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			}
		]
	}`

	ast := asset.Asset{
		ID:     "arn:aws:iam::123456789012:role/FallbackRole",
		Type:   kernel.AssetType("iam_role"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"identity": map[string]any{
				"policies_json": adminPolicy,
				"scp_json":      adminPolicy, // Include SCP to mark SCPPresent = true
			},
		},
	}

	snap := asset.Snapshot{
		SchemaVersion: "1",
		CapturedAt:    time.Now(),
		Source:        "test",
		Assets:        []asset.Asset{ast},
	}

	tmpDir, err := os.MkdirTemp("", "stave-nep-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	snapFile := filepath.Join(tmpDir, "snapshot.json")
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("failed to marshal snapshots: %v", err)
	}
	if err := os.WriteFile(snapFile, data, 0600); err != nil {
		t.Fatalf("failed to write snapshot file: %v", err)
	}

	// Resolve the principal using our config
	cfg := PrincipalConfig{
		Snapshot:     snapFile,
		PrincipalARN: "arn:aws:iam::123456789012:role/FallbackRole",
		Format:       "json",
	}

	outBytes, err := ResolvePrincipal(cfg)
	if err != nil {
		t.Fatalf("ResolvePrincipal failed: %v", err)
	}

	var res struct {
		IsAdmin        bool   `json:"is_admin"`
		PrivilegeLevel string `json:"privilege_level"`
	}
	if err := json.Unmarshal(outBytes, &res); err != nil {
		t.Fatalf("failed to unmarshal output: %v\nOutput: %s", err, string(outBytes))
	}

	// Under the buggy code: since the fallback asset's policies are ignored,
	// IsAdmin will be false and PrivilegeLevel will be "none".
	// Under correct behavior: it should be recognized as an admin principal.
	if !res.IsAdmin {
		t.Errorf("expected principal to be admin, got IsAdmin=false, PrivilegeLevel=%q (ignored policy on asset fallback)", res.PrivilegeLevel)
	}
}
