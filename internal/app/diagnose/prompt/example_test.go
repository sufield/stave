package prompt_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	promptout "github.com/sufield/stave/internal/adapters/output/prompt"
	diagprompt "github.com/sufield/stave/internal/app/diagnose/prompt"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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

func testLoadEval(path string) (*evaluation.Result, error) {
	return (&evaljson.Loader{}).LoadFromFile(path)
}

func testBuildPrompt(
	assetID string,
	controlsByID map[kernel.ControlID]*policy.ControlDefinition,
	assetPropsJSON string,
	matched []evaluation.Finding,
) diagprompt.PromptOutput {
	builder := &promptout.PromptBuilder{
		AssetID:        assetID,
		ControlsByID:   controlsByID,
		AssetPropsJSON: assetPropsJSON,
	}
	data := builder.Build(matched)
	rendered := promptout.RenderPrompt(data)

	findingIDs := make([]kernel.ControlID, len(data.Findings))
	for i, f := range data.Findings {
		findingIDs[i] = f.ControlID
	}
	return diagprompt.PromptOutput{
		Rendered:   rendered,
		FindingIDs: findingIDs,
		AssetID:    data.AssetID,
	}
}

func testContext(ctlByID map[kernel.ControlID]*policy.ControlDefinition, propsJSON string) diagprompt.DiagnosticContext {
	return diagprompt.DiagnosticContext{
		ControlsByID:   ctlByID,
		AssetPropsJSON: propsJSON,
		LoadEval:       testLoadEval,
		BuildPrompt:    testBuildPrompt,
	}
}

func TestNewRunnerRun(t *testing.T) {
	dir := t.TempDir()
	evalFile := writeEvalFile(t, dir)

	dctx := testContext(
		map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.S3.PUBLIC.001": {
				ID:          "CTL.S3.PUBLIC.001",
				Name:        "S3 Public Access",
				Description: "S3 bucket allows public read access",
			},
		},
		`{"public_access": true}`,
	)

	var stdout, stderr bytes.Buffer
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(diagprompt.Config{
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

	dctx := testContext(nil, "")
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(diagprompt.Config{
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
	dctx := testContext(nil, "")
	runner := diagprompt.NewRunner(dctx)

	t.Run("missing eval file", func(t *testing.T) {
		err := runner.Run(diagprompt.Config{
			AssetID: "x",
			Stdout:  &bytes.Buffer{},
			Stderr:  &bytes.Buffer{},
		})
		if err == nil || !strings.Contains(err.Error(), "--evaluation-file") {
			t.Fatalf("expected eval file error, got: %v", err)
		}
	})

	t.Run("missing asset id", func(t *testing.T) {
		err := runner.Run(diagprompt.Config{
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

	dctx := testContext(
		map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.S3.PUBLIC.001": {
				ID:   "CTL.S3.PUBLIC.001",
				Name: "S3 Public Access",
			},
		},
		"",
	)

	var stdout bytes.Buffer
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(diagprompt.Config{
		EvalFile: evalFile,
		AssetID:  "aws:s3:::test-bucket",
		Format:   appcontracts.FormatJSON,
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

func TestNewRunnerRunLoadError(t *testing.T) {
	dctx := diagprompt.DiagnosticContext{
		LoadEval: func(string) (*evaluation.Result, error) {
			return nil, fmt.Errorf("simulated load error")
		},
		BuildPrompt: testBuildPrompt,
	}
	runner := diagprompt.NewRunner(dctx)
	err := runner.Run(diagprompt.Config{
		EvalFile: "nonexistent.json",
		AssetID:  "x",
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "simulated load error") {
		t.Fatalf("expected load error, got: %v", err)
	}
}
