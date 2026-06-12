package forge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
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
// on every call.
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

// runNonInteractive validates the opts, runs the gencontrol tool as a
// subprocess (a repo-local dev tool), and validates the generated control via
// the facade. The subprocess + flag validation stay command-side; only the
// generated-YAML validation crosses into pkg/stave.
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
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // G204: args built from validated CLI flags passed as a slice — no shell interpolation
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gencontrol failed: %w", err)
	}

	fmt.Fprintln(w, "\nGeneration complete.")

	// Validate the generated control YAML via the facade. A non-nil error
	// propagates so the command fails non-zero rather than silently shipping
	// a broken control.
	out, err := stave.ForgeValidateGenerated(opts.ID, opts.Out)
	if _, werr := w.Write(out); werr != nil && err == nil {
		return fmt.Errorf("write validation output: %w", werr)
	}
	return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
}
