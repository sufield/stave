package evaluate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
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
	// Empty snapshot — no assets to derive account from.
	snap := asset.Snapshot{}
	got := extractAccountID(snap)
	if got != "" {
		t.Fatalf("got %q, want empty for snapshot with no assets", got)
	}

	// Snapshot with ARN containing account ID.
	snap2 := asset.Snapshot{Assets: []asset.Asset{
		{ID: "arn:aws:s3::123456789012:bucket"},
	}}
	got2 := extractAccountID(snap2)
	if got2 != "123456789012" {
		t.Fatalf("got %q, want 123456789012", got2)
	}
}

func TestResolveOutput_Stdout(t *testing.T) {
	var buf bytes.Buffer
	w, closer, err := resolveOutput("", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var nilErr error
	closer(&nilErr)
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
	var nilErr error
	defer closer(&nilErr)
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

// TestEvaluate_NoStaveYAML confirms a missing stave.yaml is not a fatal
// error: evaluate must succeed with an empty exceptions list. The
// regression this guards is straightforward — if the loader or the
// caller ever turn ErrNotExist back into a hard error, every project
// without an exceptions file would lose the ability to run evaluate.
func TestEvaluate_NoStaveYAML(t *testing.T) {
	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	snap := filepath.Join(origCwd, "testdata", "snapshots", "hipaa_fixture.json")

	// Switch to a tempdir with no stave.yaml so the cmd's
	// hardcoded "stave.yaml" lookup resolves to an absent file.
	t.Chdir(t.TempDir())

	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", snap,
		"--profile", "hipaa",
		"--format", "json",
	})

	execErr := cmd.Execute()
	// HIPAA fixture intentionally fails its checks, so the command
	// returns an exit-1 error. Guard only against the load-exceptions
	// failure mode; everything else is acceptable.
	if execErr != nil && strings.Contains(execErr.Error(), "load exceptions") {
		t.Fatalf("evaluate must not fail on missing stave.yaml: %v", execErr)
	}
}
