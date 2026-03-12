package json

import (
	"bytes"
	stdjson "encoding/json"
	"strings"
	"testing"
	"time"

	output "github.com/sufield/stave/internal/adapters/output"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/sanitize"
)

func TestWriteFindings_WithEnvelopeAndRedaction(t *testing.T) {
	w := NewFindingWriterWithEnvelope(true)
	enricher := remediation.NewMapper()
	sanitizer := sanitize.New()

	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "test",
			Offline:     true,
			Now:         now,
			MaxUnsafe:   kernel.Duration(24 * time.Hour),
			Snapshots:   1,
			InputHashes: &evaluation.InputHashes{
				Files: map[evaluation.FilePath]kernel.Digest{
					"/tmp/observations/a.json": "abc123",
				},
				Overall: "overall123",
			},
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 1,
			AttackSurface:   1,
			Violations:      1,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "No Public Bucket Access",
				ControlDescription: "Bucket must not be public",
				AssetID:            "secret-bucket",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
				Evidence:           evaluation.Evidence{},
			},
		},
	}

	enriched := output.Enrich(enricher, sanitizer, result)
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}

	var buf bytes.Buffer
	buf.Write(data)

	var payload map[string]any
	if err := stdjson.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nraw: %s", err, buf.String())
	}

	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("envelope ok = %v, want true", payload["ok"])
	}

	d, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("data type = %T, want map[string]any", payload["data"])
	}
	if d["kind"] != "evaluation" {
		t.Fatalf("kind = %v, want evaluation", d["kind"])
	}

	run, ok := d["run"].(map[string]any)
	if !ok {
		t.Fatalf("run type = %T, want map[string]any", d["run"])
	}
	inputHashes, ok := run["input_hashes"].(map[string]any)
	if !ok {
		t.Fatalf("input_hashes type = %T, want map[string]any", run["input_hashes"])
	}
	files, ok := inputHashes["files"].(map[string]any)
	if !ok {
		t.Fatalf("files type = %T, want map[string]any", inputHashes["files"])
	}
	if _, exists := files["a.json"]; !exists {
		t.Fatalf("expected sanitized hash key basename a.json, got keys: %#v", files)
	}
	if _, exists := files["/tmp/observations/a.json"]; exists {
		t.Fatalf("expected full path key to be sanitized, got keys: %#v", files)
	}

	findings, ok := d["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings shape = %T len=%d", d["findings"], len(findings))
	}
	f0 := findings[0].(map[string]any)
	if f0["asset_id"] == "secret-bucket" {
		t.Fatalf("expected asset_id to be sanitized, got %v", f0["asset_id"])
	}
}

func TestWriteFindings_WithoutEnvelope(t *testing.T) {
	w := NewFindingWriter(false)
	enricher := remediation.NewMapper()
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "test",
			Offline:     true,
			Now:         time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			MaxUnsafe:   kernel.Duration(24 * time.Hour),
			Snapshots:   0,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 0,
			AttackSurface:   0,
			Violations:      0,
		},
		Findings: nil,
	}

	enriched := output.Enrich(enricher, nil, result)
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}
	out := string(data)

	if strings.Contains(out, `"ok":`) {
		t.Fatalf("unexpected envelope in output: %s", out)
	}
	if !strings.Contains(out, `"kind":"evaluation"`) {
		t.Fatalf("missing evaluation kind: %s", out)
	}
	if !strings.Contains(out, `"findings":[]`) {
		t.Fatalf("expected normalized empty findings array: %s", out)
	}
}

func TestShouldValidateFindingContract_EnvSwitches(t *testing.T) {
	t.Setenv(env.DevValidateFindings.Name, "")
	t.Setenv(env.Debug.Name, "")
	if shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be false by default")
	}

	t.Setenv(env.DevValidateFindings.Name, "1")
	if !shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be true for STAVE_DEV_VALIDATE_FINDINGS=1")
	}

	t.Setenv(env.DevValidateFindings.Name, "")
	t.Setenv(env.Debug.Name, "1")
	if !shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be true for STAVE_DEBUG=1")
	}
}

func TestValidateFindings_InvalidFinding(t *testing.T) {
	err := validateFindings(contractvalidator.New(), []remediation.Finding{{}})
	if err == nil {
		t.Fatal("expected contract validation error for empty finding payload")
	}
}
