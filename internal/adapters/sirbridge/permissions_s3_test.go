package sirbridge

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func bucketWithPolicy(id string, policyJSON string, ownership string, bpa map[string]bool) asset.Asset {
	storage := map[string]any{
		"ownership_controls": ownership,
	}
	if bpa != nil {
		controls := map[string]any{}
		block := map[string]any{}
		for k, v := range bpa {
			block[k] = v
		}
		controls["public_access_block"] = block
		storage["controls"] = controls
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"policy_json": policyJSON,
			"storage":     storage,
		},
	}
}

func TestAWSS3PermissionAggregator_PublicReadEmitsFact(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket-a/*"
		}]
	}`
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucketWithPolicy("arn:aws:s3:::bucket-a", policyJSON, "ObjectWriter", nil),
		},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d (%+v)", len(facts), facts)
	}
	f := facts[0]
	if f.AssetID != "arn:aws:s3:::bucket-a" {
		t.Errorf("AssetID: got %q", f.AssetID)
	}
	if f.PrincipalID != "*" {
		t.Errorf("PrincipalID: want *, got %q", f.PrincipalID)
	}
	if len(f.Actions) != 1 || f.Actions[0] != "s3:GetObject" {
		t.Errorf("Actions: want [s3:GetObject], got %v", f.Actions)
	}
	// Statement source must point at idx:0 + sid:PublicRead label.
	hasStatementSource := false
	for _, s := range f.ContributingSources {
		if s.Kind == "statement" && len(s.Path) >= 3 && s.Path[2] == "PublicRead" {
			hasStatementSource = true
			break
		}
	}
	if !hasStatementSource {
		t.Errorf("expected statement source naming Sid PublicRead, got %+v", f.ContributingSources)
	}
}

func TestAWSS3PermissionAggregator_BPAFullyBlocksSuppressesPublic(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket-b/*"
		}]
	}`
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucketWithPolicy("arn:aws:s3:::bucket-b", policyJSON, "ObjectWriter", map[string]bool{
				"block_public_acls":       true,
				"ignore_public_acls":      true,
				"block_public_policy":     true,
				"restrict_public_buckets": true,
			}),
		},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 0 {
		t.Errorf("expected BPA to suppress public statement; got %d facts", len(facts))
	}
}

func TestAWSS3PermissionAggregator_BPAPolicyOnlySuppressesPublic(t *testing.T) {
	// Only BlockPublicPolicy/RestrictPublicBuckets set (not the
	// ACL ones); public statement still suppressed.
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket-c/*"
		}]
	}`
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucketWithPolicy("arn:aws:s3:::bucket-c", policyJSON, "ObjectWriter", map[string]bool{
				"block_public_acls":       false,
				"ignore_public_acls":      false,
				"block_public_policy":     true,
				"restrict_public_buckets": false,
			}),
		},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 0 {
		t.Errorf("expected BlockPublicPolicy alone to suppress; got %d facts", len(facts))
	}
}

func TestAWSS3PermissionAggregator_BucketOwnerEnforcedRecorded(t *testing.T) {
	// Wildcard principal would normally produce a public fact.
	// With BucketOwnerEnforced (ACLs disabled), the fact still
	// emits but ContributingSources must record the ownership
	// state — the SIR signals "ACLs were definitively excluded
	// from this aggregation" rather than "ACLs were unchecked."
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::111122223333:role/AppRole"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket-d/*"
		}]
	}`
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucketWithPolicy("arn:aws:s3:::bucket-d", policyJSON, "BucketOwnerEnforced", nil),
		},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	hasOwnership := false
	hasUnhydrated := false
	for _, s := range facts[0].ContributingSources {
		if s.Kind == "ownership" {
			hasOwnership = true
		}
		if s.Kind == "acl_unhydrated" {
			hasUnhydrated = true
		}
	}
	if !hasOwnership {
		t.Errorf("BucketOwnerEnforced bucket must record ownership source: %+v", facts[0].ContributingSources)
	}
	if hasUnhydrated {
		t.Errorf("BucketOwnerEnforced bucket must NOT record acl_unhydrated (ACLs definitively excluded): %+v", facts[0].ContributingSources)
	}
}

func TestAWSS3PermissionAggregator_NoPolicyYieldsNoFacts(t *testing.T) {
	bucket := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-e"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"storage": map[string]any{},
		},
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{bucket},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 0 {
		t.Errorf("bucket without policy should produce 0 facts; got %d", len(facts))
	}
}

func TestAWSS3PermissionAggregator_ValidFromValidUntilSpan(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket-f/*"
		}]
	}`
	earlier := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	later := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)
	snap1 := asset.Snapshot{
		Source: asset.SourceDeployed, CapturedAt: earlier,
		Assets: []asset.Asset{bucketWithPolicy("arn:aws:s3:::bucket-f", policyJSON, "ObjectWriter", nil)},
	}
	snap2 := asset.Snapshot{
		Source: asset.SourceDeployed, CapturedAt: later,
		Assets: []asset.Asset{bucketWithPolicy("arn:aws:s3:::bucket-f", policyJSON, "ObjectWriter", nil)},
	}

	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap1, snap2}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if !facts[0].ValidFrom.Equal(earlier) {
		t.Errorf("ValidFrom: want %v, got %v", earlier, facts[0].ValidFrom)
	}
	if !facts[0].ValidUntil.Equal(later) {
		t.Errorf("ValidUntil: want %v, got %v", later, facts[0].ValidUntil)
	}
}

func TestAWSS3PermissionAggregator_IgnoresNonS3Assets(t *testing.T) {
	other := asset.Asset{
		ID:     asset.ID("arn:aws:dynamodb:::table/X"),
		Type:   kernel.AssetType("aws_dynamodb_table"),
		Vendor: kernel.Vendor("aws"),
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{other},
	}
	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 0 {
		t.Errorf("non-S3 asset must not produce facts; got %d", len(facts))
	}
}

func TestAWSS3PermissionAggregator_ServicePrincipalLabelled(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "logging.s3.amazonaws.com"},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::bucket-g/*"
		}]
	}`
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucketWithPolicy("arn:aws:s3:::bucket-g", policyJSON, "ObjectWriter", nil),
		},
	}
	agg := NewAWSS3PermissionAggregator()
	facts, err := agg.Aggregate([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if !strings.Contains(facts[0].PrincipalID, "service:logging.s3.amazonaws.com") {
		t.Errorf("PrincipalID should label service principal: got %q", facts[0].PrincipalID)
	}
}
