package trace

import (
	"bytes"
	"context"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
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
	var buf bytes.Buffer
	runner := &Runner{}
	err := runner.Run(context.Background(), Config{
		Control:         testControl(),
		Snapshot:        testSnapshot(),
		AssetID:         "aws:s3:::test-bucket",
		ObservationPath: "test.json",
		Format:          appcontracts.FormatText,
		Stdout:          &buf,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestRunnerRun_JSON(t *testing.T) {
	var buf bytes.Buffer
	runner := &Runner{}
	err := runner.Run(context.Background(), Config{
		Control:         testControl(),
		Snapshot:        testSnapshot(),
		AssetID:         "aws:s3:::test-bucket",
		ObservationPath: "test.json",
		Format:          appcontracts.FormatJSON,
		Stdout:          &buf,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("expected control ID in JSON output, got: %s", buf.String())
	}
}

func TestRunnerRun_Quiet(t *testing.T) {
	var buf bytes.Buffer
	runner := &Runner{}
	err := runner.Run(context.Background(), Config{
		Control:  testControl(),
		Snapshot: testSnapshot(),
		AssetID:  "aws:s3:::test-bucket",
		Quiet:    true,
		Stdout:   &buf,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("expected empty output in quiet mode")
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
