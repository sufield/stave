package shadow

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// fakeSource is a minimal evaluation.FindingSource for tests.
// It returns a fixed list of findings (or an error / panic if
// configured) without invoking any real engine.
type fakeSource struct {
	findings []evaluation.Finding
	err      error
	panicMsg string
}

func (f *fakeSource) ProduceFindings(_ context.Context, _ evaluation.FindingRequest) ([]evaluation.Finding, error) {
	if f.panicMsg != "" {
		panic(f.panicMsg)
	}
	return f.findings, f.err
}

func mkFinding(controlID, assetID string, sev controldef.Severity) evaluation.Finding {
	return evaluation.Finding{
		ControlID:       kernel.ControlID(controlID),
		AssetID:         asset.ID(assetID),
		ControlSeverity: sev,
	}
}

func newCapturingLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(handler), buf
}

func TestShadow_ReturnsPrimaryFindings(t *testing.T) {
	primaryOut := []evaluation.Finding{
		mkFinding("CTL.A.001", "bucket-a", controldef.SeverityHigh),
		mkFinding("CTL.B.001", "bucket-b", controldef.SeverityMedium),
	}
	primary := &fakeSource{findings: primaryOut}
	secondary := &fakeSource{findings: []evaluation.Finding{
		mkFinding("CTL.C.001", "bucket-c", controldef.SeverityLow),
	}}
	logger, buf := newCapturingLogger()
	src := NewShadowFindingSource(primary, secondary, logger, time.Second)

	got, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err != nil {
		t.Fatalf("ProduceFindings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (primary verbatim), got %d", len(got))
	}
	if got[0].ControlID != "CTL.A.001" || got[1].ControlID != "CTL.B.001" {
		t.Errorf("primary findings altered: %+v", got)
	}

	logged := buf.String()
	if !strings.Contains(logged, "shadow") {
		t.Errorf("expected shadow log line, got %q", logged)
	}
	// Primary 2, secondary 1 → missing=2 (CTL.A and CTL.B not in
	// secondary), extra=1 (CTL.C not in primary), severity=0.
	if !strings.Contains(logged, "diverge_missing=2") {
		t.Errorf("expected diverge_missing=2, got %q", logged)
	}
	if !strings.Contains(logged, "diverge_extra=1") {
		t.Errorf("expected diverge_extra=1, got %q", logged)
	}
}

func TestShadow_PrimaryErrorSkipsSecondary(t *testing.T) {
	primaryErr := errors.New("primary boom")
	primary := &fakeSource{err: primaryErr}
	secondaryCalled := false
	secondary := fakeSourceFn(func() {
		secondaryCalled = true
	})
	logger, _ := newCapturingLogger()
	src := NewShadowFindingSource(primary, secondary, logger, time.Second)

	_, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if !errors.Is(err, primaryErr) {
		t.Fatalf("expected primary error to propagate, got %v", err)
	}
	if secondaryCalled {
		t.Errorf("secondary must not run when primary fails")
	}
}

func TestShadow_SecondaryPanicSwallowed(t *testing.T) {
	primary := &fakeSource{findings: []evaluation.Finding{
		mkFinding("CTL.X.001", "asset-x", controldef.SeverityHigh),
	}}
	secondary := &fakeSource{panicMsg: "boom in secondary"}
	logger, buf := newCapturingLogger()
	src := NewShadowFindingSource(primary, secondary, logger, time.Second)

	got, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err != nil {
		t.Fatalf("ProduceFindings must not propagate secondary panic: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected primary's 1 finding, got %d", len(got))
	}

	logged := buf.String()
	if !strings.Contains(logged, "panicked") {
		t.Errorf("expected panic to be logged, got %q", logged)
	}
}

func TestShadow_NilSecondarySkipped(t *testing.T) {
	primary := &fakeSource{findings: []evaluation.Finding{
		mkFinding("CTL.Y.001", "asset-y", controldef.SeverityLow),
	}}
	logger, buf := newCapturingLogger()
	src := NewShadowFindingSource(primary, nil, logger, time.Second)

	got, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err != nil {
		t.Fatalf("ProduceFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	// No shadow log line when secondary is nil.
	if strings.Contains(buf.String(), "shadow") {
		t.Errorf("nil secondary must not emit shadow log line, got %q", buf.String())
	}
}

func TestShadow_SeverityDivergence(t *testing.T) {
	// Same (ControlID, AssetID) but different severities — counted
	// as severity divergence.
	primary := &fakeSource{findings: []evaluation.Finding{
		mkFinding("CTL.Z.001", "asset-z", controldef.SeverityHigh),
	}}
	secondary := &fakeSource{findings: []evaluation.Finding{
		mkFinding("CTL.Z.001", "asset-z", controldef.SeverityCritical),
	}}
	logger, buf := newCapturingLogger()
	src := NewShadowFindingSource(primary, secondary, logger, time.Second)

	if _, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{}); err != nil {
		t.Fatalf("ProduceFindings: %v", err)
	}
	logged := buf.String()
	if !strings.Contains(logged, "diverge_severity=1") {
		t.Errorf("expected diverge_severity=1, got %q", logged)
	}
	if !strings.Contains(logged, "diverge_missing=0") {
		t.Errorf("expected diverge_missing=0, got %q", logged)
	}
}

// fakeSourceFn satisfies FindingSource via a callback. Used in
// TestShadow_PrimaryErrorSkipsSecondary to detect whether the
// secondary was ever invoked.
type fakeSourceFn func()

func (f fakeSourceFn) ProduceFindings(_ context.Context, _ evaluation.FindingRequest) ([]evaluation.Finding, error) {
	f()
	return nil, nil
}
