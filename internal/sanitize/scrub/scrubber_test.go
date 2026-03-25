package scrub_test

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/sanitize/scrub"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestScrubSnapshot_Resources(t *testing.T) {
	sc := scrub.NewScrubber(sanitize.New(sanitize.WithIDSanitization(true)))
	snap := asset.Snapshot{
		SchemaVersion: "obs.v0.1",
		CapturedAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{
				ID:     "my-phi-bucket",
				Type:   kernel.AssetType("storage_bucket"),
				Vendor: kernel.Vendor("aws"),
				Source: &asset.SourceRef{File: "/home/user/obs/snap1.json", Line: 5},
				Properties: map[string]any{
					"public":      true,
					"bucket_name": "my-phi-bucket",
					"external_id": "arn:aws:s3:::my-phi-bucket",
					"tags":        map[string]any{"env": "prod"},
					"policy_json": `{"Statement":[]}`,
					"acl_grants":  []any{"grant1"},
					"nested": map[string]any{
						"safe_bool":           true,
						"acl_public_grantees": []any{"AllUsers"},
					},
				},
			},
		},
	}

	scrubbed := sc.ScrubSnapshot(snap)

	if len(scrubbed.Assets) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(scrubbed.Assets))
	}
	res := scrubbed.Assets[0]

	// Asset ID should be sanitized
	if res.ID == "my-phi-bucket" {
		t.Error("Resource ID not sanitized")
	}

	// Source file should be basename
	if res.Source.File != "snap1.json" {
		t.Errorf("Source.File = %q, want snap1.json", res.Source.File)
	}

	// Sensitive keys should be removed
	for _, key := range []string{"tags", "policy_json", "acl_grants"} {
		if _, ok := res.Properties[key]; ok {
			t.Errorf("Sensitive key %q not removed", key)
		}
	}

	// Boolean fields should be preserved
	if v, ok := res.Properties["public"]; !ok || v != true {
		t.Error("Boolean field 'public' not preserved")
	}

	// Sanitized keys should have tokens
	if v, ok := res.Properties["bucket_name"].(string); !ok || v == "my-phi-bucket" {
		t.Error("bucket_name not sanitized")
	}

	// Nested map should be recursed
	nested, ok := res.Properties["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested map not preserved")
	}
	if v, ok := nested["safe_bool"]; !ok || v != true {
		t.Error("nested safe_bool not preserved")
	}
	// acl_public_grantees in nested should be removed
	if _, ok := nested["acl_public_grantees"]; ok {
		t.Error("nested acl_public_grantees not removed")
	}
}

func TestScrubSnapshot_Identities(t *testing.T) {
	sc := scrub.NewScrubber(sanitize.New(sanitize.WithIDSanitization(true)))
	snap := asset.Snapshot{
		SchemaVersion: "obs.v0.1",
		CapturedAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets:        []asset.Asset{},
		Identities: []asset.CloudIdentity{
			{
				ID:     "ident:1",
				Type:   kernel.AssetType("iam_role"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"owner":   "platform-team",
					"purpose": "signs_downloads",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 1,
					},
				},
			},
		},
	}

	scrubbed := sc.ScrubSnapshot(snap)

	if len(scrubbed.Identities) != 1 {
		t.Fatalf("Expected 1 identity, got %d", len(scrubbed.Identities))
	}
	id := scrubbed.Identities[0]

	// Identity ID should be sanitized
	if id.ID == "ident:1" {
		t.Error("Identity ID not sanitized")
	}

	if _, ok := id.Map()["owner"]; ok {
		t.Error("owner should be removed after scrub")
	}
	if _, ok := id.Map()["purpose"]; ok {
		t.Error("purpose should be removed after scrub")
	}

	// grants and scope should be preserved
	wildcard, ok := id.HasWildcard()
	if !ok || wildcard {
		t.Error("Grants not preserved")
	}
	systems, ok := id.DistinctSystems()
	if !ok || systems != 1 {
		t.Error("Scope not preserved")
	}
}

func TestScrubSnapshot_PreservesTimestamp(t *testing.T) {
	sc := scrub.NewScrubber(sanitize.New(sanitize.WithIDSanitization(true)))
	ts := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	snap := asset.Snapshot{
		SchemaVersion: "obs.v0.1",
		CapturedAt:    ts,
		Assets:        []asset.Asset{},
	}

	scrubbed := sc.ScrubSnapshot(snap)

	if !scrubbed.CapturedAt.Equal(ts) {
		t.Error("CapturedAt changed")
	}
}
