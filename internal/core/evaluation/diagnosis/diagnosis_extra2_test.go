package diagnosis

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// fmtTime
// ---------------------------------------------------------------------------

func TestFmtTime_Zero(t *testing.T) {
	if got := fmtTime(time.Time{}); got != "unknown" {
		t.Fatalf("fmtTime(zero) = %q", got)
	}
}

func TestFmtTime_NonZero(t *testing.T) {
	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	got := fmtTime(ts)
	if got != "2026-01-15T00:00:00Z" {
		t.Fatalf("fmtTime = %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractFieldPath
// ---------------------------------------------------------------------------

func TestExtractFieldPath_Empty(t *testing.T) {
	pred := policy.UnsafePredicate{}
	got := extractFieldPath(pred)
	if got != "(complex predicate)" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractFieldPath_SingleField(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.public_access"),
				Op:    predicate.OpEq,
				Value: policy.NewOperand(true),
			},
		},
	}
	got := extractFieldPath(pred)
	if got == "(complex predicate)" {
		t.Fatalf("expected field path, got %q", got)
	}
}

func TestExtractFieldPath_MultipleFields(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.public_access"),
				Op:    predicate.OpEq,
				Value: policy.NewOperand(true),
			},
			{
				Field: predicate.NewFieldPath("properties.encryption"),
				Op:    predicate.OpEq,
				Value: policy.NewOperand(false),
			},
		},
	}
	got := extractFieldPath(pred)
	if got == "(complex predicate)" {
		t.Fatalf("expected multiple fields with ..., got %q", got)
	}
}

// ---------------------------------------------------------------------------
// buildNowSkewIssue
// ---------------------------------------------------------------------------

func TestBuildNowSkewIssue_NoSkew(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	maxCaptured := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	if issue := buildNowSkewIssue(now, maxCaptured); issue != nil {
		t.Fatal("no skew should return nil")
	}
}

func TestBuildNowSkewIssue_WithSkew(t *testing.T) {
	now := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	maxCaptured := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	issue := buildNowSkewIssue(now, maxCaptured)
	if issue == nil {
		t.Fatal("expected skew issue")
	}
	if issue.Case != ScenarioViolationEvidence {
		t.Fatalf("Case = %v", issue.Case)
	}
}

func TestBuildNowSkewIssue_ZeroTimes(t *testing.T) {
	if issue := buildNowSkewIssue(time.Time{}, time.Time{}); issue != nil {
		t.Fatal("zero times should return nil")
	}
}

// ---------------------------------------------------------------------------
// buildTopFindingIssues
// ---------------------------------------------------------------------------

func TestBuildTopFindingIssues_Empty(t *testing.T) {
	if issues := buildTopFindingIssues(nil, 5); issues != nil {
		t.Fatal("nil should return nil")
	}
}

func TestBuildTopFindingIssues_LimitApplied(t *testing.T) {
	findings := make([]DiagnosticFinding, 10)
	for i := range findings {
		findings[i] = DiagnosticFinding{
			AssetID:   "bucket-1",
			ControlID: "CTL.A.001",
		}
	}
	issues := buildTopFindingIssues(findings, 3)
	if len(issues) != 3 {
		t.Fatalf("expected 3, got %d", len(issues))
	}
}

// ---------------------------------------------------------------------------
// checkTimeSpan
// ---------------------------------------------------------------------------

func TestCheckTimeSpan_SingleSnapshot(t *testing.T) {
	input := Input{
		Snapshots:         []asset.Snapshot{{CapturedAt: time.Now()}},
		MaxUnsafeDuration: 24 * time.Hour,
	}
	issue := checkTimeSpan(input)
	if issue == nil {
		t.Fatal("expected issue for single snapshot")
	}
	if issue.Signal != msgInsufficientSnapshots {
		t.Fatalf("Signal = %q", issue.Signal)
	}
}

func TestCheckTimeSpan_ShortSpan(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	input := Input{
		Snapshots: []asset.Snapshot{
			{CapturedAt: base},
			{CapturedAt: base.Add(1 * time.Hour)},
		},
		MaxUnsafeDuration: 24 * time.Hour,
	}
	issue := checkTimeSpan(input)
	if issue == nil {
		t.Fatal("expected issue for short span")
	}
	if issue.Signal != msgTimeSpanShorterThanThreshold {
		t.Fatalf("Signal = %q", issue.Signal)
	}
}

func TestCheckTimeSpan_SufficientSpan(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	input := Input{
		Snapshots: []asset.Snapshot{
			{CapturedAt: base},
			{CapturedAt: base.Add(48 * time.Hour)},
		},
		MaxUnsafeDuration: 24 * time.Hour,
	}
	issue := checkTimeSpan(input)
	if issue != nil {
		t.Fatalf("expected no issue, got %+v", issue)
	}
}

// ---------------------------------------------------------------------------
// resolveFinalizationTime
// ---------------------------------------------------------------------------

func TestResolveFinalizationTime(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	fallback := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)

	// Normal case: now is after fallback
	if got := resolveFinalizationTime(now, fallback); !got.Equal(now) {
		t.Fatalf("expected now, got %v", got)
	}

	// now is before fallback
	if got := resolveFinalizationTime(fallback.Add(-time.Hour), fallback); !got.Equal(fallback) {
		t.Fatalf("expected fallback, got %v", got)
	}

	// now is zero
	if got := resolveFinalizationTime(time.Time{}, fallback); !got.Equal(fallback) {
		t.Fatalf("expected fallback for zero now, got %v", got)
	}
}
