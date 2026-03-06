package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type testScopeMatcher struct {
	includeAll bool
}

func (m *testScopeMatcher) IsHealthBucket(tags map[string]string, _ string) bool {
	if m.includeAll {
		return true
	}
	dataDomain := strings.ToLower(strings.TrimSpace(tags["DataDomain"]))
	containsPHI := strings.ToLower(strings.TrimSpace(tags["containsPHI"]))
	return dataDomain == "health" || containsPHI == "true"
}

func defaultTestScopeMatcher() *testScopeMatcher {
	return &testScopeMatcher{}
}

func TestSnapshotExtractor_PublicBucket(t *testing.T) {
	extractor := NewSnapshotExtractor(defaultTestScopeMatcher())
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/public",
		now,
	)
	if err != nil {
		t.Fatalf("ExtractFromSnapshot failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1] // Use current snapshot
	if len(snapshot.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Resources))
	}

	resource := snapshot.Resources[0]
	if resource.ID != "acme-patient-records" {
		t.Errorf("expected bucket name 'acme-patient-records', got %q", resource.ID)
	}

	// Check policy analysis
	if allowsRead, ok := resource.Properties["policy_allows_public_read"].(bool); !ok || !allowsRead {
		t.Error("expected policy_allows_public_read=true")
	}
	if allowsList, ok := resource.Properties["policy_allows_public_list"].(bool); !ok || !allowsList {
		t.Error("expected policy_allows_public_list=true")
	}

	// Check public flag
	if isPublic, ok := resource.Properties["public"].(bool); !ok || !isPublic {
		t.Error("expected public=true")
	}

	// Check evidence
	evidence, ok := resource.Properties["evidence"].([]string)
	if !ok {
		t.Fatal("expected evidence property")
	}
	if len(evidence) == 0 {
		t.Error("expected non-empty evidence")
	}

	// Should have no missing inputs
	if missing, ok := resource.Properties["missing_inputs"].([]string); ok && len(missing) > 0 {
		t.Errorf("expected no missing inputs, got %v", missing)
	}
}

func TestSnapshotExtractor_PrivateBucket(t *testing.T) {
	extractor := NewSnapshotExtractor(defaultTestScopeMatcher())
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/private",
		now,
	)
	if err != nil {
		t.Fatalf("ExtractFromSnapshot failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	if len(snapshot.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snapshot.Resources))
	}

	resource := snapshot.Resources[0]

	// Check public access block fully blocks
	if fullyBlocked, ok := resource.Properties["public_access_fully_blocked"].(bool); !ok || !fullyBlocked {
		t.Error("expected public_access_fully_blocked=true")
	}

	// Check public flag
	if isPublic, ok := resource.Properties["public"].(bool); ok && isPublic {
		t.Error("expected public=false for private bucket")
	}
}

func TestSnapshotExtractor_MissingPolicy(t *testing.T) {
	extractor := NewSnapshotExtractor(defaultTestScopeMatcher())
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/missing-policy",
		now,
	)
	if err != nil {
		t.Fatalf("ExtractFromSnapshot failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	snapshot := snapshots[1]
	resource := snapshot.Resources[0]

	// Check missing inputs
	missing, ok := resource.Properties["missing_inputs"].([]string)
	if !ok {
		t.Fatal("expected missing_inputs property")
	}

	foundPolicyMissing := slices.Contains(missing, "get-bucket-policy/acme-incomplete-data.json")
	if !foundPolicyMissing {
		t.Errorf("expected policy to be in missing_inputs, got %v", missing)
	}

	// Check policy_status is unknown
	if status, ok := resource.Properties["policy_status"].(string); !ok || status != "unknown" {
		t.Errorf("expected policy_status='unknown', got %v", status)
	}

	// Safety should not be provable
	if provable, ok := resource.Properties["safety_provable"].(bool); ok && provable {
		t.Error("expected safety_provable=false when policy is missing")
	}
}

func TestSnapshotExtractor_Determinism(t *testing.T) {
	extractor := NewSnapshotExtractor(defaultTestScopeMatcher())
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots1, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/public",
		now,
	)
	if err != nil {
		t.Fatalf("first extraction failed: %v", err)
	}

	snapshots2, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/public",
		now,
	)
	if err != nil {
		t.Fatalf("second extraction failed: %v", err)
	}

	// Compare resource IDs
	if len(snapshots1) != len(snapshots2) {
		t.Fatalf("snapshot counts differ: %d vs %d", len(snapshots1), len(snapshots2))
	}

	for i := range snapshots1 {
		if len(snapshots1[i].Resources) != len(snapshots2[i].Resources) {
			t.Fatalf("resource counts differ in snapshot %d", i)
		}
		for j := range snapshots1[i].Resources {
			if snapshots1[i].Resources[j].ID != snapshots2[i].Resources[j].ID {
				t.Errorf("resource IDs differ at snapshot %d, resource %d", i, j)
			}
		}
	}
}

// TestSnapshotExtractor_Determinism_ByteIdentical verifies that extracting the
// same snapshot directory twice produces byte-identical JSON output. This catches
// nondeterminism in map iteration, property ordering, or timestamp handling.
func TestSnapshotExtractor_Determinism_ByteIdentical(t *testing.T) {
	extractor := NewSnapshotExtractor(&testScopeMatcher{includeAll: true})
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	var outputs [2][]byte
	for i := range 2 {
		snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
			"../../../../../../testdata/s3-snapshots/public",
			now,
		)
		if err != nil {
			t.Fatalf("run %d: extraction failed: %v", i, err)
		}

		data, err := json.MarshalIndent(snapshots, "", "  ")
		if err != nil {
			t.Fatalf("run %d: marshal failed: %v", i, err)
		}
		outputs[i] = data
	}

	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Errorf("ingest --profile mvp1-s3 output is NOT byte-identical across two runs:\n--- run 0 (first 500) ---\n%s\n--- run 1 (first 500) ---\n%s",
			truncateBytes(outputs[0], 500), truncateBytes(outputs[1], 500))
	}
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func TestSnapshotExtractor_HealthScopeFilter(t *testing.T) {
	// Default scope should filter to health buckets only
	extractor := NewSnapshotExtractor(defaultTestScopeMatcher())
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/public",
		now,
	)
	if err != nil {
		t.Fatalf("ExtractFromSnapshot failed: %v", err)
	}

	// Should include health-tagged bucket
	if len(snapshots[0].Resources) != 1 {
		t.Fatalf("expected 1 resource with health scope, got %d", len(snapshots[0].Resources))
	}
}

func TestSnapshotExtractor_IncludeAll(t *testing.T) {
	extractor := NewSnapshotExtractor(&testScopeMatcher{includeAll: true})
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots, err := extractor.ExtractFromSnapshotWithTime(context.Background(),
		"../../../../../../testdata/s3-snapshots/public",
		now,
	)
	if err != nil {
		t.Fatalf("ExtractFromSnapshot failed: %v", err)
	}

	// Should include all buckets when IncludeAll is true
	if len(snapshots[0].Resources) == 0 {
		t.Error("expected at least 1 resource with include-all")
	}
}

// TestSnapshotExtractor_RejectsBadBucketName tests that extraction fails when
// list-buckets.json contains a bucket name with path traversal characters.
func TestSnapshotExtractor_RejectsBadBucketName(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		bucketName string
		wantErr    string
	}{
		{"path separator", "bucket/escape", "invalid bucket name"},
		{"backslash", "bucket\\\\escape", "invalid bucket name"},
		{"traversal dots", "bucket..name", "invalid bucket name"},
		{"uppercase", "MyBucket", "invalid bucket name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listJSON := `{"Buckets":[{"Name":"` + tt.bucketName + `","CreationDate":"2026-01-01T00:00:00Z"}],"Owner":{"DisplayName":"test","ID":"123"}}`
			if err := os.WriteFile(filepath.Join(dir, "list-buckets.json"), []byte(listJSON), 0o600); err != nil {
				t.Fatal(err)
			}

			extractor := NewSnapshotExtractor(&testScopeMatcher{includeAll: true})
			now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

			_, err := extractor.ExtractFromSnapshotWithTime(context.Background(), dir, now)
			if err == nil {
				t.Fatalf("expected error for bucket name %q", tt.bucketName)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
