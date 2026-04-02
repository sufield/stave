package asset

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// identity_metadata.go — toIdentityInt coverage
// ---------------------------------------------------------------------------

func TestToIdentityInt_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int
		ok   bool
	}{
		{"int", int(42), 42, true},
		{"int8", int8(8), 8, true},
		{"int16", int16(16), 16, true},
		{"int32", int32(32), 32, true},
		{"int64", int64(64), 64, true},
		{"uint", uint(10), 10, true},
		{"uint8", uint8(8), 8, true},
		{"uint16", uint16(16), 16, true},
		{"uint32", uint32(32), 32, true},
		{"uint64", uint64(64), 64, true},
		{"float32", float32(3.14), 3, true},
		{"float64", float64(7.99), 7, true},
		{"string", "not a number", 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toIdentityInt(tt.in)
			if ok != tt.ok {
				t.Fatalf("toIdentityInt(%T) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("toIdentityInt(%T) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// identity_metadata.go — CloudIdentity accessors
// ---------------------------------------------------------------------------

func TestCloudIdentityMetadata(t *testing.T) {
	id := CloudIdentity{
		ID:     "role-1",
		Type:   "iam_role",
		Vendor: "aws",
		Properties: map[string]any{
			"owner":   "admin",
			"purpose": "deployment",
			"grants": map[string]any{
				"has_wildcard": true,
			},
			"scope": map[string]any{
				"distinct_systems":         float64(3),
				"distinct_resource_groups": float64(5),
			},
		},
	}

	owner, ok := id.Owner()
	if !ok || owner != "admin" {
		t.Fatalf("Owner = %v, %v", owner, ok)
	}

	purpose, ok := id.Purpose()
	if !ok || purpose != "deployment" {
		t.Fatalf("Purpose = %v, %v", purpose, ok)
	}

	hasWild, ok := id.HasWildcard()
	if !ok || !hasWild {
		t.Fatalf("HasWildcard = %v, %v", hasWild, ok)
	}

	systems, ok := id.DistinctSystems()
	if !ok || systems != 3 {
		t.Fatalf("DistinctSystems = %v, %v", systems, ok)
	}

	groups, ok := id.DistinctResourceGroups()
	if !ok || groups != 5 {
		t.Fatalf("DistinctResourceGroups = %v, %v", groups, ok)
	}

	// Metadata() method
	_ = id.Metadata()
}

func TestCloudIdentityMissingProperties(t *testing.T) {
	id := CloudIdentity{ID: "role-2"}

	_, ok := id.Owner()
	if ok {
		t.Fatal("Owner should not be found")
	}

	_, ok = id.Purpose()
	if ok {
		t.Fatal("Purpose should not be found")
	}

	_, ok = id.HasWildcard()
	if ok {
		t.Fatal("HasWildcard should not be found")
	}

	_, ok = id.DistinctSystems()
	if ok {
		t.Fatal("DistinctSystems should not be found")
	}
}

func TestCloudIdentityBadTypes(t *testing.T) {
	id := CloudIdentity{
		Properties: map[string]any{
			"owner": 42, // not a string
			"grants": map[string]any{
				"has_wildcard": "not-a-bool",
			},
			"scope": map[string]any{
				"distinct_systems": "not-a-number",
			},
		},
	}

	_, ok := id.Owner()
	if ok {
		t.Fatal("Owner should fail for non-string")
	}

	// HasWildcard parent exists, key exists but wrong type
	val, _ := id.HasWildcard()
	if val {
		t.Fatal("HasWildcard should be false for wrong type")
	}

	// scope exists, key exists, but wrong type
	_, parentOk := id.DistinctSystems()
	if !parentOk {
		t.Fatal("parent 'scope' exists so parentOk should be true")
	}
}

func TestIdentityNestedBoolProperty_BadParentType(t *testing.T) {
	props := map[string]any{
		"grants": "not-a-map",
	}
	_, parentOk := identityNestedBoolProperty(props, "grants", "has_wildcard")
	if !parentOk {
		t.Fatal("parent exists so parentOk should be true")
	}
}

func TestIdentityNestedIntProperty_BadParentType(t *testing.T) {
	props := map[string]any{
		"scope": "not-a-map",
	}
	_, parentOk := identityNestedIntProperty(props, "scope", "distinct_systems")
	if !parentOk {
		t.Fatal("parent exists so parentOk should be true")
	}
}

func TestIdentityNestedBoolProperty_MissingKey(t *testing.T) {
	props := map[string]any{
		"grants": map[string]any{},
	}
	val, parentOk := identityNestedBoolProperty(props, "grants", "has_wildcard")
	if val != false {
		t.Fatal("missing key should return false")
	}
	if !parentOk {
		t.Fatal("parent exists so parentOk should be true")
	}
}

func TestIdentityNestedIntProperty_MissingKey(t *testing.T) {
	props := map[string]any{
		"scope": map[string]any{},
	}
	val, parentOk := identityNestedIntProperty(props, "scope", "distinct_systems")
	if val != 0 {
		t.Fatal("missing key should return 0")
	}
	if !parentOk {
		t.Fatal("parent exists so parentOk should be true")
	}
}

// ---------------------------------------------------------------------------
// source_evidence.go — PolicyStatementIDs, ACLGranteeIDs
// ---------------------------------------------------------------------------

func TestPolicyStatementIDs(t *testing.T) {
	a := Asset{
		ID: "bucket-1",
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"policy_public_statements": []any{"stmt-1", "stmt-2"},
			},
		},
	}
	ids := a.PolicyStatementIDs()
	if len(ids) != 2 {
		t.Fatalf("PolicyStatementIDs = %v", ids)
	}
}

func TestACLGranteeIDs(t *testing.T) {
	a := Asset{
		ID: "bucket-1",
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"acl_public_grantees": []any{"urn:aws:iam::*"},
			},
		},
	}
	ids := a.ACLGranteeIDs()
	if len(ids) != 1 {
		t.Fatalf("ACLGranteeIDs = %v", ids)
	}
}

func TestPolicyStatementIDs_Empty(t *testing.T) {
	a := Asset{ID: "bucket-1"}
	ids := a.PolicyStatementIDs()
	if len(ids) != 0 {
		t.Fatalf("expected empty, got %v", ids)
	}
}

// ---------------------------------------------------------------------------
// stats.go — HasCoverageData
// ---------------------------------------------------------------------------

func TestObservationStats_HasCoverageData(t *testing.T) {
	s := &ObservationStats{}
	if s.HasCoverageData() {
		t.Fatal("empty stats should not have coverage data")
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = s.RecordObservation(base)
	// After one observation, first==last==base, both non-zero
	if !s.HasCoverageData() {
		t.Fatal("after one observation should have coverage data")
	}
}

// ---------------------------------------------------------------------------
// scope_filter.go — DefaultHealthcareScopeFilter, tag-based filtering
// ---------------------------------------------------------------------------

func TestDefaultHealthcareScopeFilter(t *testing.T) {
	f := DefaultHealthcareScopeFilter()
	if f == nil {
		t.Fatal("expected non-nil")
	}
	if f.includeAll {
		t.Fatal("should not be universal")
	}

	// Asset with health tag should be in scope
	a := Asset{
		ID: "bucket-1",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					"DataDomain": "health",
				},
			},
		},
	}
	if !f.IsInScope(a) {
		t.Fatal("health-tagged asset should be in scope")
	}

	// Asset without tags should not be in scope
	a2 := Asset{ID: "bucket-2"}
	if f.IsInScope(a2) {
		t.Fatal("untagged asset should not be in scope")
	}
}

func TestScopeFilter_TagRequirements(t *testing.T) {
	f := NewScopeFilter(nil, map[string][]string{
		"env":        {"prod", "staging"},
		"DataDomain": {},
	})
	if f.includeAll {
		t.Fatal("should not be universal")
	}

	// Asset matching tag value
	a := Asset{
		ID: "bucket-1",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					"env": "prod",
				},
			},
		},
	}
	if !f.IsInScope(a) {
		t.Fatal("prod env asset should be in scope")
	}

	// Asset matching key-only requirement
	a2 := Asset{
		ID: "bucket-2",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					"datadomain": "anything",
				},
			},
		},
	}
	if !f.IsInScope(a2) {
		t.Fatal("asset with DataDomain key should be in scope")
	}
}

func TestScopeFilter_WhitespaceHandling(t *testing.T) {
	// Allowlist with whitespace entries
	f := NewScopeFilter([]string{"  bucket-1  ", "", "  "}, nil)
	if f.includeAll {
		t.Fatal("should not be universal")
	}

	a := Asset{ID: "bucket-1"}
	if !f.IsInScope(a) {
		t.Fatal("trimmed bucket-1 should be in scope")
	}
}

func TestScopeFilter_EmptyTagValues(t *testing.T) {
	// Tag spec with all empty values -> key-only mode
	f := NewScopeFilter(nil, map[string][]string{
		"env": {"", "  "},
	})
	if f.includeAll {
		t.Fatal("should not be universal with key-only tag spec")
	}
}

func TestScopeFilter_DiscardableKey(t *testing.T) {
	// Empty tag key should be discarded
	f := NewScopeFilter(nil, map[string][]string{
		"  ": {"value"},
	})
	// All keys are empty, so the filter should be universal
	if !f.includeAll {
		t.Fatal("all empty keys should result in universal filter")
	}
}

// ---------------------------------------------------------------------------
// timeline.go — closeTimestamp, Stats, SetAsset edge cases
// ---------------------------------------------------------------------------

func TestTimeline_Stats(t *testing.T) {
	a := Asset{ID: "bucket-1"}
	tl, err := NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	stats := tl.Stats()
	if stats.HasFirstObservation() {
		t.Fatal("empty timeline should not have first observation")
	}
}

func TestTimeline_SetAsset_EmptyID(t *testing.T) {
	a := Asset{ID: "bucket-1"}
	tl, err := NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	// SetAsset with same ID is fine
	tl.SetAsset(Asset{ID: "bucket-1", Type: "s3_bucket"})
	if tl.Asset().Type != "s3_bucket" {
		t.Fatalf("Type = %v", tl.Asset().Type)
	}
}

// ---------------------------------------------------------------------------
// validation.go — checkDurationFeasibility, hasInsufficientSpan
// ---------------------------------------------------------------------------

func TestCheckDurationFeasibility_InsufficientSpan(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour) // 1h span
	snapshots := Snapshots{
		{CapturedAt: t1, Assets: []Asset{{ID: "b1", Type: "s3_bucket"}}},
		{CapturedAt: t2, Assets: []Asset{{ID: "b1", Type: "s3_bucket"}}},
	}
	now := t2
	maxUnsafe := 48 * time.Hour // much larger than span
	issues := snapshots.ValidateAll(now, maxUnsafe)

	found := false
	for _, issue := range issues {
		if issue.Code == "SPAN_LESS_THAN_MAX_UNSAFE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected SPAN_LESS_THAN_MAX_UNSAFE issue, got %v", issues)
	}
}

// ---------------------------------------------------------------------------
// episode.go — UnmarshalJSON edge cases
// ---------------------------------------------------------------------------

func TestEpisodeUnmarshalJSON_OpenEpisode(t *testing.T) {
	data := `{"start_at":"2026-01-01T00:00:00Z","end_at":"0001-01-01T00:00:00Z","open":true}`
	var ep Episode
	err := json.Unmarshal([]byte(data), &ep)
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if !ep.IsOpen() {
		t.Fatal("should be open")
	}
}

func TestEpisodeUnmarshalJSON_ClosedEpisode(t *testing.T) {
	data := `{"start_at":"2026-01-01T00:00:00Z","end_at":"2026-01-02T00:00:00Z","open":false}`
	var ep Episode
	err := json.Unmarshal([]byte(data), &ep)
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if ep.IsOpen() {
		t.Fatal("should be closed")
	}
}

func TestEpisodeUnmarshalJSON_MissingStartAt(t *testing.T) {
	data := `{"end_at":"2026-01-02T00:00:00Z","open":false}`
	var ep Episode
	err := json.Unmarshal([]byte(data), &ep)
	if err == nil {
		t.Fatal("expected error for missing start_at")
	}
}

func TestEpisodeUnmarshalJSON_BadJSON(t *testing.T) {
	var ep Episode
	err := json.Unmarshal([]byte(`{bad`), &ep)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// ---------------------------------------------------------------------------
// episode_history.go — WindowSummary
// ---------------------------------------------------------------------------

func TestEpisodeHistory_WindowSummary(t *testing.T) {
	h := &EpisodeHistory{}

	start1 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	end1 := start1.Add(2 * time.Hour)
	ep1, _ := NewClosedEpisode(start1, end1)
	h.Record(ep1)

	start2 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	end2 := start2.Add(3 * time.Hour)
	ep2, _ := NewClosedEpisode(start2, end2)
	h.Record(ep2)

	w := kernel.TimeWindow{
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	count, first, last := h.WindowSummary(w)
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if !first.Equal(start1) {
		t.Fatalf("first = %v", first)
	}
	if !last.Equal(end2) {
		t.Fatalf("last = %v", last)
	}
}

func TestEpisodeHistory_WindowSummary_NoMatch(t *testing.T) {
	h := &EpisodeHistory{}

	start1 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	ep1, _ := NewClosedEpisode(start1, start1.Add(time.Hour))
	h.Record(ep1)

	w := kernel.TimeWindow{
		Start: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}

	count, _, _ := h.WindowSummary(w)
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}

// ---------------------------------------------------------------------------
// delta.go — ChangeType.IsValid, ObservationDeltaSummary
// ---------------------------------------------------------------------------

func TestChangeType_IsValid(t *testing.T) {
	if !ChangeAdded.IsValid() {
		t.Fatal("ChangeAdded should be valid")
	}
	if !ChangeRemoved.IsValid() {
		t.Fatal("ChangeRemoved should be valid")
	}
	if !ChangeModified.IsValid() {
		t.Fatal("ChangeModified should be valid")
	}
	if ChangeType("unknown").IsValid() {
		t.Fatal("unknown should not be valid")
	}
}

func TestObservationDeltaSummary_Increment(t *testing.T) {
	var s ObservationDeltaSummary
	s.Increment(ChangeAdded)
	s.Increment(ChangeAdded)
	s.Increment(ChangeRemoved)
	s.Increment(ChangeModified)
	s.Increment("invalid") // should be no-op

	if s.Added() != 2 {
		t.Fatalf("Added = %d", s.Added())
	}
	if s.Removed() != 1 {
		t.Fatalf("Removed = %d", s.Removed())
	}
	if s.Modified() != 1 {
		t.Fatalf("Modified = %d", s.Modified())
	}
	if s.Total() != 4 {
		t.Fatalf("Total = %d", s.Total())
	}
}

func TestObservationDeltaSummary_MarshalJSON(t *testing.T) {
	var s ObservationDeltaSummary
	s.Increment(ChangeAdded)
	s.Increment(ChangeRemoved)

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]int
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["added"] != 1 || m["removed"] != 1 || m["total"] != 2 {
		t.Fatalf("got %v", m)
	}
}

// ---------------------------------------------------------------------------
// Asset helpers
// ---------------------------------------------------------------------------

func TestAsset_Identities_WithExternalID(t *testing.T) {
	a := Asset{
		ID: "bucket-1",
		Properties: map[string]any{
			"external_id": "arn:aws:s3:::bucket-1",
		},
	}
	ids := a.Identities()
	if len(ids) != 2 {
		t.Fatalf("Identities = %v", ids)
	}
	if ids[0] != "bucket-1" || ids[1] != "arn:aws:s3:::bucket-1" {
		t.Fatalf("Identities = %v", ids)
	}
}

func TestAsset_Identities_NoExternalID(t *testing.T) {
	a := Asset{ID: "bucket-1"}
	ids := a.Identities()
	if len(ids) != 1 || ids[0] != "bucket-1" {
		t.Fatalf("Identities = %v", ids)
	}
}

func TestAsset_Tags_Empty(t *testing.T) {
	a := Asset{ID: "bucket-1"}
	tags := a.Tags()
	// Empty tags should not match anything
	if tags.Matches("env", nil) {
		t.Fatal("empty tags should not match")
	}
}

// ---------------------------------------------------------------------------
// ExemptedAsset.Sanitized
// ---------------------------------------------------------------------------

type stubIDSanitizer struct{}

func (s *stubIDSanitizer) ID(id string) string { return "REDACTED" }

func TestExemptedAsset_Sanitized(t *testing.T) {
	ea := ExemptedAsset{
		ID:      "bucket-secret",
		Pattern: "bucket-*",
		Reason:  "test",
	}
	san := ea.Sanitized(&stubIDSanitizer{})
	if san.ID != "REDACTED" {
		t.Fatalf("ID = %v", san.ID)
	}
	if san.Pattern != "bucket-*" {
		t.Fatal("pattern should not be sanitized")
	}
}

// ---------------------------------------------------------------------------
// validation.go — FormatLatest
// ---------------------------------------------------------------------------

func TestSnapshotTimeline_FormatLatest_Nil(t *testing.T) {
	var tl *snapshotTimeline
	if tl.FormatLatest() != "" {
		t.Fatal("nil timeline should return empty string")
	}
}

func TestSnapshotTimeline_DuplicateTimes_Nil(t *testing.T) {
	var tl *snapshotTimeline
	if tl.DuplicateTimes() != nil {
		t.Fatal("nil timeline should return nil")
	}
}

func TestSnapshotTimeline_IsAheadOf_Nil(t *testing.T) {
	var tl *snapshotTimeline
	if tl.IsAheadOf(time.Now()) {
		t.Fatal("nil timeline should not be ahead of anything")
	}
}
