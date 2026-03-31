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

func TestRunnerRun_Text(t *testing.T) {
	runner := &Runner{}
	result, err := runner.Run(Config{
		Control:         testControl(),
		Snapshot:        testSnapshot(),
		AssetID:         "aws:s3:::test-bucket",
		ObservationPath: "test.json",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	var buf bytes.Buffer
	if err := result.RenderText(&buf); err != nil {
		t.Fatalf("RenderText error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestRunnerRun_JSON(t *testing.T) {
	runner := &Runner{}
	result, err := runner.Run(Config{
		Control:         testControl(),
		Snapshot:        testSnapshot(),
		AssetID:         "aws:s3:::test-bucket",
		ObservationPath: "test.json",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	var buf bytes.Buffer
	if err := result.RenderJSON(&buf); err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("expected control ID in JSON output, got: %s", buf.String())
	}
}

func TestRunnerRun_ReturnsResult(t *testing.T) {
	runner := &Runner{}
	result, err := runner.Run(Config{
		Control:         testControl(),
		Snapshot:        testSnapshot(),
		AssetID:         "aws:s3:::test-bucket",
		ObservationPath: "test.json",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestFindAsset_Found(t *testing.T) {
	snap := testSnapshot()
	a, err := FindAsset(snap, "aws:s3:::test-bucket", "test.json")
	if err != nil {
		t.Fatalf("FindAsset error: %v", err)
	}
	if a.ID != "aws:s3:::test-bucket" {
		t.Fatalf("expected test-bucket, got %s", a.ID)
	}
}

func TestFindAsset_NotFound(t *testing.T) {
	snap := testSnapshot()
	_, err := FindAsset(snap, "nonexistent", "test.json")
	if err == nil {
		t.Fatal("expected error for missing asset")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' in error, got: %v", err)
	}
}
