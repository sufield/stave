package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestSchemasTextOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSchemas(&buf, appcontracts.FormatText); err != nil {
		t.Fatalf("writeSchemas error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"ctrl.v1",
		"obs.v0.1",
		"out.v0.1",
		"diagnose.v1",
		"diff.v0.1",
		"baseline.v0.1",
		"validate.v0.1",
		"bug-report.v0.1",
		"security-audit.v1",
		"Data Contracts:",
		"Diagnostic Contracts:",
		"Command Output Contracts:",
		"Artifact Contracts:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

func TestSchemasJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSchemas(&buf, appcontracts.FormatJSON); err != nil {
		t.Fatalf("writeSchemas error: %v", err)
	}

	var got schemasOutput
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, buf.String())
	}

	if len(got.Data) == 0 {
		t.Fatal("data array must be non-empty")
	}
	if len(got.Diagnostic) == 0 {
		t.Fatal("diagnostic array must be non-empty")
	}
	if len(got.CommandOutput) == 0 {
		t.Fatal("command_output array must be non-empty")
	}
	if len(got.Artifact) == 0 {
		t.Fatal("artifact array must be non-empty")
	}

	found := map[string]bool{}
	for _, e := range got.Data {
		found[e.Schema] = true
	}
	for _, want := range []string{"ctrl.v1", "obs.v0.1", "out.v0.1"} {
		if !found[want] {
			t.Errorf("data missing schema %q", want)
		}
	}
}
