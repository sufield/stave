package forge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/adapters/observations"
)

func writeTestBundle(t *testing.T, assets []map[string]any) string {
	t.Helper()
	snapshots := []map[string]any{{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets":         assets,
	}}
	bundle := map[string]any{
		"schema_version": "obs.v0.1",
		"snapshots":      snapshots,
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestRunPaths_ListsPaths(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{{
		"id":     "bucket-1",
		"type":   "aws_s3_bucket",
		"vendor": "aws",
		"properties": map[string]any{
			"storage": map[string]any{
				"name":   "bucket-1",
				"region": "us-east-1",
				"tags": map[string]any{
					"environment": "production",
					"team":        "platform",
				},
				"encryption": map[string]any{
					"enabled": true,
				},
			},
		},
	}})

	var buf bytes.Buffer
	err := runPaths(&buf, path, "aws_s3_bucket", "")
	if err != nil {
		t.Fatalf("runPaths: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "properties.storage.name") {
		t.Error("missing storage.name path")
	}
	if !strings.Contains(out, "properties.storage.tags") {
		t.Error("missing storage.tags path")
	}
	if !strings.Contains(out, `properties.storage.tags[environment]`) {
		t.Error("missing expanded tag key")
	}
	if !strings.Contains(out, "bool") {
		t.Error("missing bool type for encryption.enabled")
	}
}

func TestRunPaths_FilterWorks(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{{
		"id": "bucket-1", "type": "aws_s3_bucket", "vendor": "aws",
		"properties": map[string]any{
			"storage": map[string]any{
				"name":       "b",
				"encryption": map[string]any{"enabled": true},
			},
		},
	}})

	var buf bytes.Buffer
	err := runPaths(&buf, path, "aws_s3_bucket", "encryption")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "encryption") {
		t.Error("filter should show encryption paths")
	}
	// name should be filtered out
	if strings.Contains(out, "properties.storage.name") {
		t.Error("filter should exclude non-matching paths")
	}
}

func TestRunPreview_DetectsUnsafe(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{
		{
			"id": "public-bucket", "type": "aws_s3_bucket", "vendor": "aws",
			"properties": map[string]any{
				"storage": map[string]any{
					"access": map[string]any{"public_read": true},
				},
			},
		},
		{
			"id": "private-bucket", "type": "aws_s3_bucket", "vendor": "aws",
			"properties": map[string]any{
				"storage": map[string]any{
					"access": map[string]any{"public_read": false},
				},
			},
		},
	})

	var buf bytes.Buffer
	err := runPreview(&buf, path, "aws_s3_bucket",
		"properties.storage.access.public_read", "eq", "true", "")
	if err != nil {
		t.Fatalf("runPreview: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "FAIL") {
		t.Error("expected at least one FAIL")
	}
	if !strings.Contains(out, "PASS") {
		t.Error("expected at least one PASS")
	}
	if !strings.Contains(out, "1 FAIL") {
		t.Error("expected exactly 1 FAIL")
	}
}

func TestWizard_ReadLine(t *testing.T) {
	input := strings.NewReader("hello world\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readLine("prompt:")
	if got != "hello world" {
		t.Errorf("readLine = %q, want %q", got, "hello world")
	}
}

func TestWizard_ReadLineDefault(t *testing.T) {
	input := strings.NewReader("\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readLineDefault("prompt:", "default")
	if got != "default" {
		t.Errorf("readLineDefault = %q, want %q", got, "default")
	}
}

func TestWizard_SelectOption(t *testing.T) {
	input := strings.NewReader("2\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.selectOption("pick:", []string{"a", "b", "c"})
	if got != "b" {
		t.Errorf("selectOption = %q, want %q", got, "b")
	}
}

func TestWizard_Confirm(t *testing.T) {
	input := strings.NewReader("n\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	if w.confirm("ok?") {
		t.Error("expected false for 'n' input")
	}
}

func TestWizard_ReadControlID(t *testing.T) {
	input := strings.NewReader("bad\nCTL.S3.TAGS.001\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readControlID()
	if got != "CTL.S3.TAGS.001" {
		t.Errorf("readControlID = %q, want CTL.S3.TAGS.001", got)
	}
}

func TestControlIDPattern(t *testing.T) {
	valid := []string{"CTL.S3.TAGS.001", "CTL.IAM.ROOT.002", "CTL.VPC.SG.123"}
	for _, id := range valid {
		if !controlIDPattern.MatchString(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}
	invalid := []string{"CTL.S3", "ctl.s3.tags.001", "CTL.S3.TAGS", "SOMETHING.ELSE"}
	for _, id := range invalid {
		if controlIDPattern.MatchString(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}

func TestDiscoverAssetTypes_FromSnapshot(t *testing.T) {
	snap := writeTestBundle(t, []map[string]any{
		{"id": "a", "type": "aws_s3_bucket", "vendor": "aws", "properties": map[string]any{}},
		{"id": "b", "type": "aws_iam_role", "vendor": "aws", "properties": map[string]any{}},
	})

	snapshots, _ := observations.LoadBundle(snap)
	types := discoverAssetTypes(&snapshots[0])
	if len(types) != 2 {
		t.Errorf("expected 2 types, got %d", len(types))
	}
}
