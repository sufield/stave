package eval

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	clockadp "github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
	aws "github.com/sufield/stave/internal/platform/providers/aws"
)

// hitCounterHandler is a minimal slog.Handler that counts how many
// "assessment cache hit" records the workflow emits. Used to confirm
// the second PerformAssessment call genuinely served from the cache
// (so the Metadata assertion is meaningful, not a false negative from
// two cold runs).
type hitCounterHandler struct {
	mu   sync.Mutex
	hits int
}

func (h *hitCounterHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *hitCounterHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "assessment cache hit") {
		h.mu.Lock()
		h.hits++
		h.mu.Unlock()
	}
	return nil
}

func (h *hitCounterHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *hitCounterHandler) WithGroup(string) slog.Handler      { return h }

// Test_RedGate_CacheHitMetadata asserts that a warm cache hit returns
// a ComplianceReport carrying the same provenance Metadata (and thus
// the same out.v0.1 extensions block) as the cold run that produced
// it. ComplianceReport.Metadata is json:"-" (audit.go:350), so the
// assessment cache's JSON round-trip drops it. On a cache MISS,
// Evaluate re-attaches it (evaluate_workflow.go:126); on a cache HIT
// (workflow.go:214-226) only rehydrateControlRemediation runs and
// Metadata is left at its zero value. ToExtensions() then returns nil
// when ControlSource.Source == "" (extensions_dto.go:25), so the
// warm-hit output silently omits the entire extensions block
// (selected_controls_source, context_name, resolved_paths, ...).
func Test_RedGate_CacheHitMetadata(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during cache-hit metadata test: %v", r)
		}
	}()

	// Isolate and enable a real, clean assessment cache. os.UserCacheDir
	// honours XDG_CACHE_HOME on Linux; pointing it at a fresh TempDir
	// gives the workflow a writable cache directory with no pre-existing
	// entries, and clearing the kill-switch ensures the cache is active.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("STAVE_DISABLE_ASSESSMENT_CACHE", "")

	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	ctl := policy.ControlDefinition{
		ID:          "CTL.TEST.PUBLIC.001",
		Name:        "Public resource",
		Description: "Detect public resources",
		Type:        policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("ctl.Prepare: %v", err)
	}
	resource := asset.Asset{
		ID:         "res-1",
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{"public": true},
	}
	snapshots := []asset.Snapshot{
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: aws.SourceTypeAWSS3Snapshot},
			CapturedAt:  now.Add(-2 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: aws.SourceTypeAWSS3Snapshot},
			CapturedAt:  now.Add(-1 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
	}

	// Digests must be valid 64-char lowercase hex: kernel.Digest's
	// UnmarshalText rejects shorter values, which would make the
	// cache's JSON round-trip fail to decode and mask the real bug.
	fileDigest := kernel.Digest(strings.Repeat("a", 64))
	overallDigest := kernel.Digest(strings.Repeat("b", 64))

	hits := &hitCounterHandler{}
	run, err := NewAuditWorkflow(
		evalObservationRepoStub{
			snapshots: snapshots,
			hashes: &evaluation.InputHashes{
				Files:   map[evaluation.FilePath]kernel.Digest{"a.json": fileDigest},
				Overall: overallDigest,
			},
		},
		evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
		&marshalerStub{},
		testEnrichFn,
	)
	if err != nil {
		t.Fatalf("NewAuditWorkflow: %v", err)
	}
	run.Logger = slog.New(hits)

	// Provenance the cold run records and that the warm hit must
	// preserve byte-for-byte in its output extensions block.
	meta := evaluation.Metadata{
		ContextName: "foo",
		ControlSource: evaluation.ControlSourceInfo{
			Source: evaluation.ControlSourceDir,
		},
		ResolvedPaths: evaluation.ResolvedPaths{
			Controls:     "/abs/controls",
			Observations: "/abs/observations",
		},
	}

	cfg := AssessmentConfig{
		ObservationConfig: ObservationConfig{
			PolicySource:      "ctl",
			ObservationSource: "obs",
		},
		SLAThreshold:    30 * time.Minute,
		Clock:           clockadp.FixedClock(now),
		PredicateParser: noopPredicateParser,
		PredicateEval:   mustPredicateEval(),
		BuildVersion:    "test-version",
		Metadata:        meta,
	}

	// Cold run: cache miss, persists the report.
	report1, _, err := run.PerformAssessment(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first PerformAssessment: %v", err)
	}
	if report1.Metadata.ToExtensions() == nil {
		t.Fatalf("precondition failed: cold-run report must carry extensions metadata, got nil; "+
			"Source=%q", report1.Metadata.ControlSource.Source)
	}

	// Warm run: same inputs -> cache hit.
	report2, _, err := run.PerformAssessment(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second PerformAssessment: %v", err)
	}

	// Sanity: confirm the second call really was a cache hit, otherwise
	// the assertion below proves nothing.
	hits.mu.Lock()
	gotHits := hits.hits
	hits.mu.Unlock()
	if gotHits == 0 {
		t.Fatalf("precondition failed: second run was not a cache hit (hits=%d); "+
			"cache may be disabled or keys diverged", gotHits)
	}

	// CORRECT behaviour: the warm cache hit must carry the same
	// provenance Metadata as the cold run, so the emitted extensions
	// block is identical across runs.
	got := report2.Metadata.ToExtensions()
	if got == nil {
		t.Fatalf("cache-hit report dropped extensions metadata: ToExtensions()==nil; "+
			"cold run had Source=%q ContextName=%q ResolvedPaths=%+v. "+
			"Metadata is json:\"-\" and is not re-attached on a cache hit.",
			report1.Metadata.ControlSource.Source,
			report1.Metadata.ContextName,
			report1.Metadata.ResolvedPaths)
	}
	want := report1.Metadata.ToExtensions()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cache-hit extensions block diverges from cold run:\n  cold: %+v\n  warm: %+v", want, got)
	}
}
