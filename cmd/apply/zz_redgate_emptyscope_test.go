package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Test_RedGate_EmptyScope asserts the CORRECT behavior for the
// profile-mode empty-scope path (profile.go:194 Runner.Run).
//
// When a --bucket-allowlist scopes out every asset, filterSnapshots
// returns empty and Run currently returns nil at line 195 — a clean
// exit-0 "compliant" outcome that emits NO output document. For a
// --format json consumer this is the "one document per invocation"
// contract violation: stdout is empty yet the run looks successful,
// making a mis-scoped (typo) allowlist indistinguishable from a
// genuinely clean account.
//
// The standard apply path always emits an output document. This test
// asserts the same for profile mode: a JSON invocation must produce a
// parseable JSON document on stdout. Against current code stdout is
// empty, so the test fails (RED).
func Test_RedGate_EmptyScope(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in empty-scope run: %v", r)
		}
	}()

	// Reuse a real, schema-valid observation bundle that contains S3
	// bucket assets. The bundle ships in repo testdata and is loaded
	// by observations.LoadBundle inside Runner.Run.
	repoRoot := findRepoRoot(t)
	inputFile := filepath.Join(repoRoot, "testdata", "e2e", "aws-s3-obs-public", "observations.json")

	var stdout, stderr bytes.Buffer
	rt := ui.NewRuntime(&stdout, &stderr)
	f := compose.DefaultFactories()
	runner := NewRunner(
		f.NewCELEvaluator,
		func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
			return compose.LoadControlsFrom(ctx, f.NewCtlRepo, dir)
		},
		f.NewFindingWriter,
		WithUI(rt),
	)

	cfg := Config{
		InputFile: inputFile,
		Profile:   ProfileAWSS3,
		Profiles:  []Profile{ProfileAWSS3},
		// A typo ARN matches no asset identity, so the allowlist scope
		// removes every snapshot/asset -> filtered is empty.
		BucketAllowlist: []string{"arn:aws:s3:::typo-bucket-that-matches-nothing"},
		OutputFormat:    appcontracts.OutputFormat("json"),
		Stdout:          &stdout,
		Stderr:          &stderr,
	}

	err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run returned error: %v\nstderr: %s", err, stderr.String())
	}

	// CORRECT behavior: a --format json invocation emits exactly one
	// output document on stdout. Empty stdout means no document was
	// produced -> the empty-scope short-circuit broke the contract.
	out := stdout.Bytes()
	if len(bytes.TrimSpace(out)) == 0 {
		t.Fatalf("empty-scope --format json run produced NO output document on stdout (exit 0, no JSON); a jq consumer parses nothing and the run looks compliant")
	}
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("stdout is not a parseable JSON document: %v\nstdout: %s", err, string(out))
	}
}
