package forge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type nonInteractiveOpts struct {
	ID          string
	Name        string
	Domain      string
	Severity    string
	ScopeTags   string
	AssetType   string
	Kind        string
	Field       string
	Op          string
	Value       string
	Remediation string
	Compliance  string
	Out         string
}

// Args returns the gencontrol invocation argv built from these opts.
// Encapsulates the per-field "skip when default / skip when empty"
// rules so runNonInteractive doesn't reproduce twelve inline checks
// on every call. Field defaults are listed inline next to their
// flag so a future default change is one edit on the type.
func (o nonInteractiveOpts) Args() []string {
	args := []string{
		"run", "./internal/tools/gencontrol",
		"--id", o.ID,
		"--name", o.Name,
		"--field", o.Field,
		"--remediation", o.Remediation,
	}
	type optional struct {
		flag, value, defaultValue string
		appendOnEmpty             bool // true = emit even when default
	}
	for _, f := range []optional{
		{"--domain", o.Domain, "exposure", false},
		{"--severity", o.Severity, "high", false},
		{"--scope-tags", o.ScopeTags, "aws", false},
		{"--asset-type", o.AssetType, "aws_s3_bucket", false},
		{"--kind", o.Kind, "", true},
		{"--op", o.Op, "eq", false},
		{"--value", o.Value, "true", false},
		{"--compliance", o.Compliance, "", true},
		{"--out", o.Out, "testdata/e2e", false},
	} {
		if f.value == "" {
			continue
		}
		if !f.appendOnEmpty && f.value == f.defaultValue {
			continue
		}
		args = append(args, f.flag, f.value)
	}
	return args
}

func runNonInteractive(ctx context.Context, w io.Writer, opts nonInteractiveOpts) error {
	if opts.ID == "" || opts.Name == "" || opts.Field == "" || opts.Remediation == "" {
		return errors.New("--id, --name, --field, and --remediation are required in non-interactive mode")
	}
	if err := fsutil.SafeFilename(opts.ID); err != nil {
		return fmt.Errorf("--id: %w", err)
	}
	if opts.Out != "" {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return fmt.Errorf("cannot determine working directory: %w", cwdErr)
		}
		if _, dirErr := fsutil.SafeDir(opts.Out, cwd); dirErr != nil {
			return fmt.Errorf("--out: %w", dirErr)
		}
	}

	args := opts.Args()

	fmt.Fprintf(w, "Generating control %s...\n", opts.ID)

	// Arguments are built from validated CLI flag values and passed
	// as a slice to exec.Command — no shell interpolation occurs.
	// G204: subprocess launched with variable — safe, no shell.
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // G204: args built from validated CLI flags passed as a slice — no shell interpolation
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gencontrol failed: %w", err)
	}

	fmt.Fprintln(w, "\nGeneration complete.")

	// Validate the generated control YAML. Validation errors propagate
	// so the command fails non-zero rather than silently shipping a
	// broken control.
	return validateGeneratedControl(w, opts.ID, opts.Out)
}

// validateGeneratedControl finds and validates the generated control YAML
// using the same parsing path as stave validate. Returns nil on success;
// returns a non-nil error when the expected YAML is absent (generation
// produced nothing) or exists but fails to parse or prepare.
//
// This runs immediately after a generation step that is always expected to
// write <controlID>.yaml, so a missing file is a pipeline failure — not a
// benign "nothing to validate" skip.
func validateGeneratedControl(w io.Writer, controlID, outDir string) error {
	if outDir == "" {
		outDir = "testdata/e2e"
	}

	// Match the EXACT filename gencontrol writes (<controlID>.yaml), not
	// merely a basename that contains the ID. A substring match would let
	// a sibling like <controlID>_v2.yaml (or an unrelated control whose ID
	// contains this one) be validated in place of the real output, so an
	// invalid generated control could pass on the strength of a different
	// file. Surface walk errors instead of swallowing them — a
	// permission-denied or vanished subtree used to silently produce the
	// SKIPPED path, masking the real cause from the operator.
	wantName := controlID + ".yaml"
	var yamlPath string
	walkErr := filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == wantName {
			yamlPath = path
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(w, "\nValidating generated control...  WARNING\n  walk error: %v\n", walkErr)
		// Continue — the file may still have been found before the
		// walk encountered the problematic entry.
	}

	if yamlPath == "" {
		// Generation just ran and was expected to write wantName. Its
		// absence means the pipeline produced no control — fail loud
		// rather than reporting SKIPPED success and shipping nothing.
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  expected %s under %s but it was not generated\n", wantName, outDir)
		if walkErr != nil {
			return fmt.Errorf("generated control %s not found under %s (walk error: %w)", wantName, outDir, walkErr)
		}
		return fmt.Errorf("generated control %s not found under %s — generation produced no output", wantName, outDir)
	}

	data, err := fsutil.ReadFileLimited(yamlPath)
	if err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		return fmt.Errorf("read generated control %s: %w", yamlPath, err)
	}

	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(w, "\nThe generated control has a schema error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return fmt.Errorf("parse generated control %s: %w", yamlPath, err)
	}

	if err := ctl.Prepare(); err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(w, "\nThe generated control has a preparation error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return fmt.Errorf("prepare generated control %s: %w", yamlPath, err)
	}

	fmt.Fprintln(w, "\nValidating generated control...  OK")
	return nil
}
