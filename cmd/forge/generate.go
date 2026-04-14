package forge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func runNonInteractive(ctx context.Context, w io.Writer, opts nonInteractiveOpts) error {
	if opts.ID == "" || opts.Name == "" || opts.Field == "" || opts.Remediation == "" {
		return errors.New("--id, --name, --field, and --remediation are required in non-interactive mode")
	}

	args := []string{
		"run", "./internal/tools/gencontrol",
		"--id", opts.ID,
		"--name", opts.Name,
		"--field", opts.Field,
		"--remediation", opts.Remediation,
	}

	if opts.Domain != "" && opts.Domain != "exposure" {
		args = append(args, "--domain", opts.Domain)
	}
	if opts.Severity != "" && opts.Severity != "high" {
		args = append(args, "--severity", opts.Severity)
	}
	if opts.ScopeTags != "" && opts.ScopeTags != "aws" {
		args = append(args, "--scope-tags", opts.ScopeTags)
	}
	if opts.AssetType != "" && opts.AssetType != "aws_s3_bucket" {
		args = append(args, "--asset-type", opts.AssetType)
	}
	if opts.Kind != "" {
		args = append(args, "--kind", opts.Kind)
	}
	if opts.Op != "" && opts.Op != "eq" {
		args = append(args, "--op", opts.Op)
	}
	if opts.Value != "" && opts.Value != "true" {
		args = append(args, "--value", opts.Value)
	}
	if opts.Compliance != "" {
		args = append(args, "--compliance", opts.Compliance)
	}
	if opts.Out != "" && opts.Out != "testdata/e2e" {
		args = append(args, "--out", opts.Out)
	}

	fmt.Fprintf(w, "Generating control %s...\n", opts.ID)

	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // args built from validated CLI flags
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gencontrol failed: %w", err)
	}

	fmt.Fprintln(w, "\nGeneration complete.")

	// Validate the generated control YAML.
	validateGeneratedControl(w, opts.ID, opts.Out)

	return nil
}

// validateGeneratedControl finds and validates the generated control YAML
// using the same parsing path as stave validate.
func validateGeneratedControl(w io.Writer, controlID, outDir string) {
	if outDir == "" {
		outDir = "testdata/e2e"
	}

	// Find the generated YAML by walking the output directory for the control ID.
	var yamlPath string
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") && strings.Contains(filepath.Base(path), controlID) {
			yamlPath = path
			return filepath.SkipAll
		}
		return nil
	})

	if yamlPath == "" {
		fmt.Fprintln(w, "\nValidating generated control...  SKIPPED (YAML file not found)")
		return
	}

	data, err := fsutil.ReadFileLimited(yamlPath)
	if err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		return
	}

	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(w, "\nThe generated control has a schema error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return
	}

	if err := ctl.Prepare(); err != nil {
		fmt.Fprintf(w, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(w, "\nThe generated control has a preparation error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return
	}

	fmt.Fprintln(w, "\nValidating generated control...  OK")
}
