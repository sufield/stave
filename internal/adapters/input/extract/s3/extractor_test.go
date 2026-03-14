package s3

import (
	"context"
	"testing"

	"github.com/sufield/stave/internal/domain/asset"
)

// getStorageMap extracts the "storage" sub-map from an asset's Properties.
func getStorageMap(t *testing.T, resource asset.Asset) map[string]any {
	t.Helper()
	storage, ok := resource.Properties["storage"].(map[string]any)
	if !ok {
		t.Fatal("expected storage property")
	}
	return storage
}

// getSubMap extracts a named sub-map from a parent map.
func getSubMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	sub, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s property", key)
	}
	return sub
}

// assertBoolField asserts that m[key] is a bool with the expected value.
func assertBoolField(t *testing.T, m map[string]any, key string, want bool) {
	t.Helper()
	got, ok := m[key].(bool)
	if want {
		if !ok || !got {
			t.Errorf("expected %s=true", key)
		}
	} else {
		if ok && got {
			t.Errorf("expected %s=false", key)
		}
	}
}

// assertStringField asserts that m[key] is a string with the expected value.
func assertStringField(t *testing.T, m map[string]any, key string, want string) {
	t.Helper()
	got, _ := m[key].(string)
	if got != want {
		t.Errorf("expected %s=%q, got %q", key, want, got)
	}
}

// assertIntField asserts that m[key] is an int with the expected value.
func assertIntField(t *testing.T, m map[string]any, key string, want int) {
	t.Helper()
	got, _ := m[key].(int)
	if got != want {
		t.Errorf("expected %s=%d, got %d", key, want, got)
	}
}

// extractResources runs ExtractFromFile, asserts 2 snapshots and the expected
// asset count in the current (second) snapshot, and returns assets keyed by ID.
func extractResources(t *testing.T, fixturePath string, scope *ScopeConfig, wantResources int) map[string]asset.Asset {
	t.Helper()
	extractor := NewExtractor(scope)

	snapshots, err := extractor.ExtractFromFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != wantResources {
		t.Fatalf("expected %d resources, got %d", wantResources, len(snapshot.Assets))
	}

	byID := make(map[string]asset.Asset, len(snapshot.Assets))
	for _, r := range snapshot.Assets {
		byID[string(r.ID)] = r
	}
	return byID
}

// resourceCase pairs an asset ID with a validation function for table-driven subtests.
type resourceCase struct {
	id       string
	validate func(t *testing.T, resource asset.Asset)
}

func TestExtractPublicBucket(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-public/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource (health-tagged), got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	if resource.ID != "acme-phi-data-bucket" {
		t.Errorf("expected bucket name 'acme-phi-data-bucket', got %q", resource.ID)
	}

	storage := getStorageMap(t, resource)
	visibility := getSubMap(t, storage, "access")

	assertBoolField(t, visibility, "public_read", true)
	assertBoolField(t, visibility, "public_list", true)

	// Root-cause attribution: policy-only public (no public ACL in this fixture)
	assertBoolField(t, visibility, "read_via_identity", true)
	assertBoolField(t, visibility, "read_via_resource", false)
	assertBoolField(t, visibility, "list_via_identity", true)
}

func TestExtractPrivateBucket(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-private/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	// Extractor returns 2 snapshots (past and present) for duration-based violation detection
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	// Use the second (current) snapshot for property validation
	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]

	// Check canonical storage model
	storage := getStorageMap(t, resource)
	controls := getSubMap(t, storage, "controls")
	assertBoolField(t, controls, "public_access_fully_blocked", true)

	// Check effective PAB flags (all 4 true for private bucket)
	pab := getSubMap(t, controls, "public_access_block")
	eff := getSubMap(t, pab, "effective")
	assertBoolField(t, eff, "block_public_acls", true)
	assertBoolField(t, eff, "ignore_public_acls", true)
	assertBoolField(t, eff, "block_public_policy", true)
	assertBoolField(t, eff, "restrict_public_buckets", true)

	visibility := getSubMap(t, storage, "access")

	// Check visibility is false when fully blocked
	assertBoolField(t, visibility, "public_read", false)

	// Root-cause fields: no public policy or ACL in this fixture
	assertBoolField(t, visibility, "read_via_identity", false)
	assertBoolField(t, visibility, "read_via_resource", false)
	assertBoolField(t, visibility, "list_via_identity", false)

	// Check vendor-specific evidence
	vendor := getSubMap(t, resource.Properties, "vendor")
	aws := getSubMap(t, vendor, "aws")
	s3Evidence := getSubMap(t, aws, "s3")
	vendorPAB := getSubMap(t, s3Evidence, "public_access_block")
	assertBoolField(t, vendorPAB, "block_public_acls", true)
}

func TestExtractHealthScopeFilter(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-health-tagged-public/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	// Extractor returns 2 snapshots (past and present) for duration-based violation detection
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	// Use the second (current) snapshot for property validation
	snapshot := snapshots[1]
	// Should only include the health-tagged bucket, not the marketing bucket
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource (health scope filtered), got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	if resource.ID != "acme-patient-records" {
		t.Errorf("expected health-tagged bucket 'acme-patient-records', got %q", resource.ID)
	}
}

func TestExtractAccountPublicAccessBlock(t *testing.T) {
	extractor := NewExtractor(&ScopeConfig{IncludeAll: true})

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-account-block/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	if resource.ID != "acme-public-bucket" {
		t.Errorf("expected bucket name 'acme-public-bucket', got %q", resource.ID)
	}

	storage := getStorageMap(t, resource)

	// Account-level block should override: post-PAB visibility must be false
	visibility := getSubMap(t, storage, "access")
	assertBoolField(t, visibility, "public_read", false)

	// Root-cause fields are pre-PAB: policy grants public read, so via_policy should be true
	assertBoolField(t, visibility, "read_via_identity", true)
	assertBoolField(t, visibility, "read_via_resource", false)

	// Latent fields: policy public read blocked by PAB = latent exposure
	assertBoolField(t, visibility, "latent_public_read", true)
	assertBoolField(t, visibility, "latent_public_list", false)

	// Check controls reflect both bucket-level and account-level state
	controls := getSubMap(t, storage, "controls")
	assertBoolField(t, controls, "public_access_fully_blocked", true)
	assertBoolField(t, controls, "account_public_access_fully_blocked", true)

	// Check account + effective PAB flags (all 4 true from account-level)
	pab := getSubMap(t, controls, "public_access_block")
	account := getSubMap(t, pab, "account")
	assertBoolField(t, account, "block_public_acls", true)
	assertBoolField(t, account, "ignore_public_acls", true)
	assertBoolField(t, account, "block_public_policy", true)
	assertBoolField(t, account, "restrict_public_buckets", true)
	eff := getSubMap(t, pab, "effective")
	assertBoolField(t, eff, "block_public_policy", true)
}

func TestExtractEncryptionCanonicalFields(t *testing.T) {
	resources := extractResources(t, "../../../../../testdata/extract/s3/plan-encryption/terraform-plan.json", &ScopeConfig{IncludeAll: true}, 3)

	cases := []resourceCase{
		{"kms-encrypted-bucket", func(t *testing.T, r asset.Asset) {
			encryption := getSubMap(t, getStorageMap(t, r), "encryption")
			assertStringField(t, encryption, "algorithm", "aws:kms")
			assertStringField(t, encryption, "kms_key_id", "arn:aws:kms:us-east-1:123456789012:key/abcd-1234")
			assertBoolField(t, encryption, "at_rest_enabled", true)
		}},
		{"aes-encrypted-bucket", func(t *testing.T, r asset.Asset) {
			encryption := getSubMap(t, getStorageMap(t, r), "encryption")
			assertStringField(t, encryption, "algorithm", "AES256")
			assertStringField(t, encryption, "kms_key_id", "")
		}},
		{"no-encryption-bucket", func(t *testing.T, r asset.Asset) {
			encryption := getSubMap(t, getStorageMap(t, r), "encryption")
			assertBoolField(t, encryption, "at_rest_enabled", false)
			assertStringField(t, encryption, "algorithm", "")
			assertStringField(t, encryption, "kms_key_id", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resources[tc.id]
			if !ok {
				t.Fatalf("resource %q not found", tc.id)
			}
			tc.validate(t, r)
		})
	}
}

func TestExtractVersioningMFADelete(t *testing.T) {
	resources := extractResources(t, "../../../../../testdata/extract/s3/plan-versioning/terraform-plan.json", &ScopeConfig{IncludeAll: true}, 3)

	cases := []resourceCase{
		{"mfa-enabled-bucket", func(t *testing.T, r asset.Asset) {
			versioning := getSubMap(t, getStorageMap(t, r), "versioning")
			assertBoolField(t, versioning, "enabled", true)
			assertBoolField(t, versioning, "mfa_delete_enabled", true)
		}},
		{"mfa-disabled-bucket", func(t *testing.T, r asset.Asset) {
			versioning := getSubMap(t, getStorageMap(t, r), "versioning")
			assertBoolField(t, versioning, "enabled", true)
			assertBoolField(t, versioning, "mfa_delete_enabled", false)
		}},
		{"no-versioning-bucket", func(t *testing.T, r asset.Asset) {
			versioning := getSubMap(t, getStorageMap(t, r), "versioning")
			assertBoolField(t, versioning, "enabled", false)
			assertBoolField(t, versioning, "mfa_delete_enabled", false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resources[tc.id]
			if !ok {
				t.Fatalf("resource %q not found", tc.id)
			}
			tc.validate(t, r)
		})
	}
}

func TestExtractLoggingTargetFields(t *testing.T) {
	resources := extractResources(t, "../../../../../testdata/extract/s3/plan-logging/terraform-plan.json", &ScopeConfig{IncludeAll: true}, 3)

	cases := []resourceCase{
		{"logged-with-prefix", func(t *testing.T, r asset.Asset) {
			logging := getSubMap(t, getStorageMap(t, r), "logging")
			assertBoolField(t, logging, "enabled", true)
			assertStringField(t, logging, "target_bucket", "central-logs-bucket")
			assertStringField(t, logging, "target_prefix", "s3-access-logs/")
		}},
		{"logged-no-prefix", func(t *testing.T, r asset.Asset) {
			logging := getSubMap(t, getStorageMap(t, r), "logging")
			assertBoolField(t, logging, "enabled", true)
			assertStringField(t, logging, "target_bucket", "central-logs-bucket")
			assertStringField(t, logging, "target_prefix", "")
		}},
		{"no-logging-bucket", func(t *testing.T, r asset.Asset) {
			logging := getSubMap(t, getStorageMap(t, r), "logging")
			assertBoolField(t, logging, "enabled", false)
			assertStringField(t, logging, "target_bucket", "")
			assertStringField(t, logging, "target_prefix", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resources[tc.id]
			if !ok {
				t.Fatalf("resource %q not found", tc.id)
			}
			tc.validate(t, r)
		})
	}
}

func TestExtractLifecycleConfig(t *testing.T) {
	resources := extractResources(t, "../../../../../testdata/extract/s3/plan-lifecycle/terraform-plan.json", &ScopeConfig{IncludeAll: true}, 7)

	cases := []resourceCase{
		{"single-expiration-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", true)
			assertIntField(t, lc, "rule_count", 1)
			assertBoolField(t, lc, "has_expiration", true)
			assertIntField(t, lc, "min_expiration_days", 365)
		}},
		{"disabled-rule-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", false)
		}},
		{"mixed-rules-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", true)
			assertIntField(t, lc, "rule_count", 2)
			assertIntField(t, lc, "min_expiration_days", 90)
		}},
		{"transition-only-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", true)
			assertBoolField(t, lc, "has_transition", true)
			assertBoolField(t, lc, "has_expiration", false)
			assertIntField(t, lc, "min_expiration_days", 0)
		}},
		{"noncurrent-version-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "has_noncurrent_version_expiration", true)
		}},
		{"no-lifecycle-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", false)
			assertIntField(t, lc, "rule_count", 0)
		}},
		{"empty-rules-bucket", func(t *testing.T, r asset.Asset) {
			lc := getSubMap(t, getStorageMap(t, r), "lifecycle")
			assertBoolField(t, lc, "rules_configured", false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resources[tc.id]
			if !ok {
				t.Fatalf("resource %q not found", tc.id)
			}
			tc.validate(t, r)
		})
	}
}

func TestExtractObjectLockConfig(t *testing.T) {
	resources := extractResources(t, "../../../../../testdata/extract/s3/plan-object-lock/terraform-plan.json", &ScopeConfig{IncludeAll: true}, 5)

	cases := []resourceCase{
		{"compliance-lock-bucket", func(t *testing.T, r asset.Asset) {
			ol := getSubMap(t, getStorageMap(t, r), "object_lock")
			assertBoolField(t, ol, "enabled", true)
			assertStringField(t, ol, "mode", "COMPLIANCE")
			assertIntField(t, ol, "retention_days", 2190)
		}},
		{"governance-years-bucket", func(t *testing.T, r asset.Asset) {
			ol := getSubMap(t, getStorageMap(t, r), "object_lock")
			assertBoolField(t, ol, "enabled", true)
			assertStringField(t, ol, "mode", "GOVERNANCE")
			assertIntField(t, ol, "retention_days", 2555)
		}},
		{"lock-no-rule-bucket", func(t *testing.T, r asset.Asset) {
			ol := getSubMap(t, getStorageMap(t, r), "object_lock")
			assertBoolField(t, ol, "enabled", true)
			assertStringField(t, ol, "mode", "")
			assertIntField(t, ol, "retention_days", 0)
		}},
		{"bucket-level-lock", func(t *testing.T, r asset.Asset) {
			ol := getSubMap(t, getStorageMap(t, r), "object_lock")
			assertBoolField(t, ol, "enabled", true)
			assertStringField(t, ol, "mode", "")
			assertIntField(t, ol, "retention_days", 0)
		}},
		{"no-lock-bucket", func(t *testing.T, r asset.Asset) {
			ol := getSubMap(t, getStorageMap(t, r), "object_lock")
			assertBoolField(t, ol, "enabled", false)
			assertStringField(t, ol, "mode", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resources[tc.id]
			if !ok {
				t.Fatalf("resource %q not found", tc.id)
			}
			tc.validate(t, r)
		})
	}
}

func TestExtractACLOnlyPublicRead(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-acl-public/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	if resource.ID != "acme-acl-public-bucket" {
		t.Errorf("expected bucket 'acme-acl-public-bucket', got %q", resource.ID)
	}

	storage := getStorageMap(t, resource)
	visibility := getSubMap(t, storage, "access")

	// ACL-only public: public_read=true via ACL, not via policy
	assertBoolField(t, visibility, "public_read", true)
	assertBoolField(t, visibility, "public_list", false)

	// Root-cause attribution
	assertBoolField(t, visibility, "read_via_identity", false)
	assertBoolField(t, visibility, "read_via_resource", true)
	assertBoolField(t, visibility, "list_via_identity", false)
}

func TestExtractPartialPAB(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-partial-pab/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	storage := getStorageMap(t, resource)
	controls := getSubMap(t, storage, "controls")

	// 3/4 flags true => NOT fully blocked
	assertBoolField(t, controls, "public_access_fully_blocked", false)

	// Check individual effective PAB flags
	pab := getSubMap(t, controls, "public_access_block")
	eff := getSubMap(t, pab, "effective")
	assertBoolField(t, eff, "block_public_acls", true)
	assertBoolField(t, eff, "ignore_public_acls", true)
	assertBoolField(t, eff, "block_public_policy", true)
	assertBoolField(t, eff, "restrict_public_buckets", false)

	// With block_public_policy=true, policy-based public read is blocked
	visibility := getSubMap(t, storage, "access")
	assertBoolField(t, visibility, "public_read", false)
	assertBoolField(t, visibility, "read_via_identity", true)
	assertBoolField(t, visibility, "latent_public_read", true)
}

func TestExtractLatentPublicList(t *testing.T) {
	extractor := NewExtractor(DefaultScopeConfig())

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-latent-list/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Assets) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Assets))
	}

	resource := snapshot.Assets[0]
	if resource.ID != "latent-listable-bucket" {
		t.Errorf("expected bucket name 'latent-listable-bucket', got %q", resource.ID)
	}

	storage := getStorageMap(t, resource)
	visibility := getSubMap(t, storage, "access")

	// PAB fully blocks effective exposure
	assertBoolField(t, visibility, "public_list", false)

	// Policy still grants listing (pre-PAB root cause)
	assertBoolField(t, visibility, "list_via_identity", true)

	// Latent: policy grants list but PAB blocks it
	assertBoolField(t, visibility, "latent_public_list", true)

	// No latent read (no read policy)
	assertBoolField(t, visibility, "latent_public_read", false)

	// Verify PAB is fully blocking
	controls := getSubMap(t, storage, "controls")
	assertBoolField(t, controls, "public_access_fully_blocked", true)
}

func TestExtractIncludeAllScope(t *testing.T) {
	extractor := NewExtractor(&ScopeConfig{IncludeAll: true})

	snapshots, err := extractor.ExtractFromFile(context.Background(), "../../../../../testdata/extract/s3/plan-health-tagged-public/terraform-plan.json")
	if err != nil {
		t.Fatalf("ExtractFromFile failed: %v", err)
	}

	// Extractor returns 2 snapshots (past and present) for duration-based violation detection
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	// Use the second (current) snapshot for property validation
	snapshot := snapshots[1]
	// Should include both buckets when IncludeAll is true
	if len(snapshot.Assets) != 2 {
		t.Fatalf("expected 2 resources (include all), got %d", len(snapshot.Assets))
	}
}
