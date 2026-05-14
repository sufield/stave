package sirbridge

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

func TestNewEngineCoverageSource_RejectsZeroMinSpan(t *testing.T) {
	// engine.NewCoverageValidator forbids zero/negative minSpan;
	// the adapter must surface that contract by failing
	// construction rather than producing a permissive validator.
	if _, err := NewEngineCoverageSource(0, time.Hour); err == nil {
		t.Fatal("NewEngineCoverageSource(0, 1h): want error, got nil")
	}
}

func TestNewEngineCoverageSource_RejectsMaxGapAboveMinSpan(t *testing.T) {
	if _, err := NewEngineCoverageSource(time.Hour, 2*time.Hour); err == nil {
		t.Fatal("NewEngineCoverageSource(1h, 2h): want error, got nil")
	}
}

func TestEngineCoverageSource_ReportsPolicyAndEmptyGapsWhenLifecyclesNil(t *testing.T) {
	src, err := NewEngineCoverageSource(12*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	report, err := src.Coverage(nil, nil)
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if report.Policy.MinRequiredSpan != 12*time.Hour {
		t.Errorf("Policy.MinRequiredSpan: want 12h, got %s", report.Policy.MinRequiredSpan)
	}
	if report.Policy.MaxAllowedGap != 12*time.Hour {
		t.Errorf("Policy.MaxAllowedGap: want 12h, got %s", report.Policy.MaxAllowedGap)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("Gaps: want empty, got %d rows", len(report.Gaps))
	}
}

func TestEngineCoverageSource_OversizedGapProducesRow(t *testing.T) {
	// Two observations 24h apart, maxAllowedGap = 12h. The
	// validator must report "max gap exceeds threshold" and the
	// adapter must surface one CoverageGap row anchored on the
	// asset's observed window.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	lc, lcErr := asset.NewExposureLifecycle(a)
	if lcErr != nil {
		t.Fatalf("NewExposureLifecycle: %v", lcErr)
	}
	t0 := now.Add(-25 * time.Hour)
	t1 := now.Add(-1 * time.Hour)
	if err := lc.RecordCheck(t0, false); err != nil {
		t.Fatalf("RecordCheck t0: %v", err)
	}
	if err := lc.RecordCheck(t1, false); err != nil {
		t.Fatalf("RecordCheck t1: %v", err)
	}

	src, err := NewEngineCoverageSource(12*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	report, err := src.Coverage(nil, map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
		kernel.ControlID("CTL.S3.PUBLIC.001"): {a.ID: lc},
	})
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if len(report.Gaps) != 1 {
		t.Fatalf("Gaps: want 1, got %d", len(report.Gaps))
	}
	g := report.Gaps[0]
	if g.AssetID != "arn:aws:s3:::bucket-a" {
		t.Errorf("AssetID: got %q", g.AssetID)
	}
	if !g.Start.Equal(t0) {
		t.Errorf("Start: want %s, got %s", t0, g.Start)
	}
	if !g.End.Equal(t1) {
		t.Errorf("End: want %s, got %s", t1, g.End)
	}
	if !strings.Contains(g.Reason, "exceeds threshold") {
		t.Errorf("Reason: want max-gap message, got %q", g.Reason)
	}
}

func TestEngineCoverageSource_DedupesAcrossControls(t *testing.T) {
	// Same asset appearing in multiple per-control lifecycles
	// produces a single row keyed on (AssetID, Reason) — coverage
	// is an observation property, not a control property.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	mkLC := func() *asset.ExposureLifecycle {
		lc, _ := asset.NewExposureLifecycle(a)
		_ = lc.RecordCheck(now.Add(-25*time.Hour), false)
		_ = lc.RecordCheck(now.Add(-1*time.Hour), false)
		return lc
	}
	src, err := NewEngineCoverageSource(12*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	report, err := src.Coverage(nil, map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
		kernel.ControlID("CTL.S3.PUBLIC.001"):     {a.ID: mkLC()},
		kernel.ControlID("CTL.S3.ENCRYPTION.001"): {a.ID: mkLC()},
	})
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if len(report.Gaps) != 1 {
		t.Fatalf("Gaps: want 1 after dedupe, got %d", len(report.Gaps))
	}
}

func TestEngineCoverageSource_NoGapWhenCadenceUnderLimit(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	lc, _ := asset.NewExposureLifecycle(a)
	for h := 24; h > 0; h-- {
		// Hourly observations across 24h: span = 23h ≥ 12h, max
		// gap = 1h ≤ 12h, so the validator declares coverage
		// sufficient and no row is emitted.
		_ = lc.RecordCheck(now.Add(-time.Duration(h)*time.Hour), false)
	}
	src, err := NewEngineCoverageSource(12*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	report, err := src.Coverage(nil, map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
		kernel.ControlID("CTL.S3.PUBLIC.001"): {a.ID: lc},
	})
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("Gaps: want 0 under sufficient cadence, got %d (%+v)", len(report.Gaps), report.Gaps)
	}
}

func TestEngineCoverageSource_RoundTripThroughBuilder(t *testing.T) {
	// End-to-end smoke test: an adapter-fed Builder produces a
	// Document whose Temporal.Coverage carries the configured
	// thresholds and whose Gaps reflect the validator's verdict.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	snap1 := asset.Snapshot{Source: asset.SourceDeployed, CapturedAt: now.Add(-25 * time.Hour), Assets: []asset.Asset{a}}
	snap2 := asset.Snapshot{Source: asset.SourceDeployed, CapturedAt: now.Add(-time.Hour), Assets: []asset.Asset{a}}

	lcSrc := NewEngineLifecycleSource(stubPredicateEval)
	covSrc, err := NewEngineCoverageSource(12*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	b := sir.NewBuilder(
		sir.WithLifecycleSource(lcSrc),
		sir.WithCoverageSource(covSrc),
	)
	doc, err := b.Build(nil, []asset.Snapshot{snap1, snap2}, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc.Temporal.Coverage.MaxAllowedGap != 12*time.Hour {
		t.Errorf("Coverage.MaxAllowedGap: want 12h, got %s", doc.Temporal.Coverage.MaxAllowedGap)
	}
	// No lifecycle produced because predicate evaluator says
	// "secure"; the coverage source still independently inspects
	// observation cadence — but with no per-control lifecycles to
	// inspect, Gaps is empty. The Coverage policy block remains
	// populated either way (proving "policy ran, nothing tripped").
	if len(doc.Temporal.Gaps) != 0 {
		t.Errorf("Gaps: want 0 when no per-control lifecycle exists, got %d", len(doc.Temporal.Gaps))
	}
}
