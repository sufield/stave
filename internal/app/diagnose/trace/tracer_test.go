package trace

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func testControl() policy.ControlDefinition {
	ctl := policy.ControlDefinition{
		ID:          "CTL.TEST.001",
		Name:        "Test control",
		Description: "Detects public access",
		Type:        policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	_ = ctl.Prepare()
	return ctl
}

func testSnapshot() *asset.Snapshot {
	return &asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID: "aws:s3:::test-bucket",
				Properties: map[string]any{
					"public": true,
				},
			},
		},
	}
}

func TestPolicyTracer_Trace_Text(t *testing.T) {
	tracer := &PolicyTracer{}
	result, err := tracer.Trace(TraceRequest{
		Control:    testControl(),
		Snapshot:   testSnapshot(),
		TargetID:   "aws:s3:::test-bucket",
		SourcePath: "test.json",
	})
	if err != nil {
		t.Fatalf("Trace error: %v", err)
	}
	var buf bytes.Buffer
	if err := result.RenderText(&buf); err != nil {
		t.Fatalf("RenderText error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestPolicyTracer_Trace_JSON(t *testing.T) {
	tracer := &PolicyTracer{}
	result, err := tracer.Trace(TraceRequest{
		Control:    testControl(),
		Snapshot:   testSnapshot(),
		TargetID:   "aws:s3:::test-bucket",
		SourcePath: "test.json",
	})
	if err != nil {
		t.Fatalf("Trace error: %v", err)
	}
	var buf bytes.Buffer
	if err := result.RenderJSON(&buf); err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("expected control ID in JSON output, got: %s", buf.String())
	}
}

func TestPolicyTracer_Trace_ReturnsResult(t *testing.T) {
	tracer := &PolicyTracer{}
	result, err := tracer.Trace(TraceRequest{
		Control:    testControl(),
		Snapshot:   testSnapshot(),
		TargetID:   "aws:s3:::test-bucket",
		SourcePath: "test.json",
	})
	if err != nil {
		t.Fatalf("Trace error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestLocateResource_Found(t *testing.T) {
	snap := testSnapshot()
	a, err := LocateResource(snap, "aws:s3:::test-bucket", "test.json")
	if err != nil {
		t.Fatalf("LocateResource error: %v", err)
	}
	if a.ID != "aws:s3:::test-bucket" {
		t.Fatalf("expected test-bucket, got %s", a.ID)
	}
}

func TestLocateResource_NotFound(t *testing.T) {
	snap := testSnapshot()
	_, err := LocateResource(snap, "nonexistent", "test.json")
	if err == nil {
		t.Fatal("expected error for missing resource")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' in error, got: %v", err)
	}
}
