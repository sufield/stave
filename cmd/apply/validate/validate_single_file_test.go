package validate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestRunValidateSingleFile_ContractControlV1(t *testing.T) {
	tmp := t.TempDir()
	inFile := filepath.Join(tmp, "ctl.yaml")
	if err := os.WriteFile(inFile, []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
`), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	opts := defaultOptions()
	opts.InFile = inFile
	opts.Kind = "control"
	opts.SchemaVersion = "v1"
	opts.StrictMode = true
	opts.Format = "text"

	format, _ := ui.ParseOutputFormat(opts.Format)
	var buf bytes.Buffer
	if err := runValidateSingleFileWithOptions(&cobra.Command{Use: "test"}, &buf, opts, format); err != nil {
		t.Fatalf("expected contract validate success, got %v", err)
	}
	if !strings.Contains(buf.String(), "Validation passed") {
		t.Fatalf("expected validation passed output, got: %s", buf.String())
	}
}

func TestRunValidateSingleFile_ContractStrictUnknownField(t *testing.T) {
	tmp := t.TempDir()
	inFile := filepath.Join(tmp, "ctl.yaml")
	if err := os.WriteFile(inFile, []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
unexpected: true
`), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	opts := defaultOptions()
	opts.InFile = inFile
	opts.Kind = "control"
	opts.SchemaVersion = "v1"
	opts.StrictMode = true
	opts.Format = "text"

	format, _ := ui.ParseOutputFormat(opts.Format)
	var buf bytes.Buffer
	err := runValidateSingleFileWithOptions(&cobra.Command{Use: "test"}, &buf, opts, format)
	if err == nil {
		t.Fatal("expected strict contract validation failure")
	}
	if ui.ExitCode(err) != 2 {
		t.Fatalf("expected exit code 2, got %d", ui.ExitCode(err))
	}
}

func TestRunValidateSingleFile_ContractRejectsInvalidControl(t *testing.T) {
	tmp := t.TempDir()
	inFile := filepath.Join(tmp, "invalid-ctl.yaml")
	if err := os.WriteFile(inFile, []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Invalid control
description: Invalid metadata shape
control: public_access
expect: disabled
`), 0o644); err != nil {
		t.Fatalf("write invalid control: %v", err)
	}

	opts := defaultOptions()
	opts.InFile = inFile
	opts.Kind = "control"
	opts.SchemaVersion = "v1"
	opts.StrictMode = true
	opts.Format = "text"

	format, _ := ui.ParseOutputFormat(opts.Format)
	var buf bytes.Buffer
	err := runValidateSingleFileWithOptions(&cobra.Command{Use: "test"}, &buf, opts, format)
	if err == nil {
		t.Fatal("expected contract validation failure for invalid shape")
	}
	if ui.ExitCode(err) != 2 {
		t.Fatalf("expected exit code 2, got %d", ui.ExitCode(err))
	}
}
