package evaluate

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExitCode_Nil(t *testing.T) {
	if ExitCode(nil) != 0 {
		t.Fatal("expected 0 for nil error")
	}
}

func TestExitCode_ExitError(t *testing.T) {
	err := &exitError{code: 1, msg: "test"}
	if ExitCode(err) != 1 {
		t.Fatalf("expected 1, got %d", ExitCode(err))
	}
}

func TestExitCode_OtherError(t *testing.T) {
	err := io.EOF
	if ExitCode(err) != 2 {
		t.Fatalf("expected 2, got %d", ExitCode(err))
	}
}

func TestExitError_Error(t *testing.T) {
	err := &exitError{code: 1, msg: "something failed"}
	if err.Error() != "something failed" {
		t.Fatalf("got %q", err.Error())
	}
}

func TestValidateSchema_Valid(t *testing.T) {
	err := validateSchema(kernel.SchemaObservation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSchema_Invalid(t *testing.T) {
	err := validateSchema("obs.v999")
	if err == nil {
		t.Fatal("expected error for invalid schema")
	}
	if !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractBucketName_FromProperties(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:         "arn:aws:s3:::my-bucket",
				Properties: map[string]any{"bucket_name": "my-bucket"},
			},
		},
	}
	got := extractBucketName(snap)
	if got != "my-bucket" {
		t.Fatalf("got %q, want my-bucket", got)
	}
}

func TestExtractBucketName_FromAssetID(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:         "some-id",
				Properties: map[string]any{},
			},
		},
	}
	got := extractBucketName(snap)
	if got != "some-id" {
		t.Fatalf("got %q, want some-id", got)
	}
}

func TestExtractBucketName_NoAssets(t *testing.T) {
	snap := asset.Snapshot{}
	got := extractBucketName(snap)
	if got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
}

func TestExtractAccountID(t *testing.T) {
	snap := asset.Snapshot{}
	got := extractAccountID(snap)
	if got != "000000000000" {
		t.Fatalf("got %q, want 000000000000", got)
	}
}

func TestResolveOutput_Stdout(t *testing.T) {
	var buf bytes.Buffer
	w, closer, err := resolveOutput("", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closer()
	if w != &buf {
		t.Fatal("expected stdout writer")
	}
}

func TestResolveOutput_File(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/output.json"
	w, closer, err := resolveOutput(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closer()
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestAllRegistries(t *testing.T) {
	regs := allRegistries()
	if len(regs) == 0 {
		t.Fatal("expected at least one registry")
	}
}
