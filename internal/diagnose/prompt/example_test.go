package prompt_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
	diagprompt "github.com/sufield/stave/internal/diagnose/prompt"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// writeEvalFile creates a minimal evaluation JSON file for testing.
func writeEvalFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "evaluation.json")
	data := []byte(`{
  "findings": [
    {
      "control_id": "CTL.S3.PUBLIC.001",
      "control_name": "S3 Public Access",
      "control_description": "S3 bucket allows public read access",
      "asset_id": "aws:s3:::test-bucket",
      "asset_type": "s3_bucket"
    }
  ]
}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewRunnerRun(t *testing.T) {
	dir := t.TempDir()
	evalFile := writeEvalFile(t, dir)

	dctx := diagprompt.DiagnosticContext{
		ControlsByID: map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.S3.PUBLIC.001": {
				ID:          "CTL.S3.PUBLIC.001",
				Name:        "S3 Public Access",
				Description: "S3 bucket allows public read access",
			},
		},
		AssetPropsJSON: `{"public_access": true}`,
	}

	var stdout, stderr bytes.Buffer
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(context.Background(), diagprompt.Config{
		EvalFile: evalFile,
		AssetID:  "aws:s3:::test-bucket",
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	got := stdout.String()
	for _, want := range []string{
		"CTL.S3.PUBLIC.001",
		"test-bucket",
		"S3 Public Access",
		"public_access",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestNewRunnerRunNoFindings(t *testing.T) {
	dir := t.TempDir()
	evalFile := writeEvalFile(t, dir)

	runner := diagprompt.NewRunner(diagprompt.DiagnosticContext{})
	err := runner.Run(context.Background(), diagprompt.Config{
		EvalFile: evalFile,
		AssetID:  "aws:s3:::nonexistent-bucket",
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "no findings") {
		t.Fatalf("expected 'no findings' error, got: %v", err)
	}
}

func TestNewRunnerRunValidation(t *testing.T) {
	runner := diagprompt.NewRunner(diagprompt.DiagnosticContext{})

	t.Run("missing eval file", func(t *testing.T) {
		err := runner.Run(context.Background(), diagprompt.Config{
			AssetID: "x",
			Stdout:  &bytes.Buffer{},
			Stderr:  &bytes.Buffer{},
		})
		if err == nil || !strings.Contains(err.Error(), "--evaluation-file") {
			t.Fatalf("expected eval file error, got: %v", err)
		}
	})

	t.Run("missing asset id", func(t *testing.T) {
		err := runner.Run(context.Background(), diagprompt.Config{
			EvalFile: "x.json",
			Stdout:   &bytes.Buffer{},
			Stderr:   &bytes.Buffer{},
		})
		if err == nil || !strings.Contains(err.Error(), "--asset-id") {
			t.Fatalf("expected asset-id error, got: %v", err)
		}
	})
}

func TestNewRunnerRunJSON(t *testing.T) {
	dir := t.TempDir()
	evalFile := writeEvalFile(t, dir)

	dctx := diagprompt.DiagnosticContext{
		ControlsByID: map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.S3.PUBLIC.001": {
				ID:   "CTL.S3.PUBLIC.001",
				Name: "S3 Public Access",
			},
		},
	}

	var stdout bytes.Buffer
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(context.Background(), diagprompt.Config{
		EvalFile: evalFile,
		AssetID:  "aws:s3:::test-bucket",
		Format:   ui.OutputFormatJSON,
		Stdout:   &stdout,
		Stderr:   &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	got := stdout.String()
	for _, want := range []string{`"prompt"`, `"finding_ids"`, `"asset_id"`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON output missing %q", want)
		}
	}
}
