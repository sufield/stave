package forge

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func newLintCmd() *cobra.Command {
	var controlPath, format string

	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Static analysis for control YAML files",
		Long: `Validate control YAML files for schema correctness, CEL predicate
syntax, and completeness.

Exit Codes:
  0   No errors (warnings/info may be present)
  1   One or more errors found
  2   Invalid input
  4   Internal error`,
		Example: `  stave forge lint --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml
  stave forge lint --control controls/`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runForgeLint(cmd.OutOrStdout(), controlPath, format)
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "control YAML file or directory (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text | json")
	_ = cmd.MarkFlagRequired("control")

	return cmd
}

type lintResult struct {
	ControlID string   `json:"control_id"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Infos     []string `json:"infos,omitempty"`
}

func runForgeLint(w io.Writer, controlPath, _ string) error {
	paths, err := collectControlPaths(controlPath)
	if err != nil {
		return err
	}

	celEval, celErr := stavecel.NewPredicateEval()
	if celErr != nil {
		return fmt.Errorf("init CEL: %w", celErr)
	}

	totalErrors := 0
	totalWarnings := 0

	for _, p := range paths {
		result := lintControl(p, celEval)
		totalErrors += len(result.Errors)
		totalWarnings += len(result.Warnings)

		if len(result.Errors)+len(result.Warnings)+len(result.Infos) == 0 {
			continue
		}

		fmt.Fprintf(w, "%s\n", result.ControlID)
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  ERROR   %s\n", e)
		}
		for _, wn := range result.Warnings {
			fmt.Fprintf(w, "  WARNING %s\n", wn)
		}
		for _, info := range result.Infos {
			fmt.Fprintf(w, "  INFO    %s\n", info)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%d error(s), %d warning(s) across %d file(s)\n",
		totalErrors, totalWarnings, len(paths))

	if totalErrors > 0 {
		return fmt.Errorf("%d lint error(s)", totalErrors)
	}
	return nil
}

func lintControl(path string, celEval policy.PredicateEval) lintResult {
	result := lintResult{ControlID: filepath.Base(path)}

	data, err := os.ReadFile(path) //nolint:gosec // user path
	if err != nil {
		result.Errors = append(result.Errors, "cannot read file: "+err.Error())
		return result
	}

	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		result.Errors = append(result.Errors, "YAML parse error: "+err.Error())
		return result
	}

	result.ControlID = string(ctl.ID)

	// Schema checks.
	if ctl.ID == "" {
		result.Errors = append(result.Errors, "missing required field: id")
	}
	if ctl.Name == "" {
		result.Errors = append(result.Errors, "missing required field: name")
	}
	if ctl.Description == "" {
		result.Errors = append(result.Errors, "missing required field: description")
	}
	if ctl.Type == 0 {
		result.Errors = append(result.Errors, "missing required field: type")
	}
	if ctl.Severity == 0 {
		result.Warnings = append(result.Warnings, "missing optional field: severity")
	}
	if len(ctl.Compliance) == 0 {
		result.Warnings = append(result.Warnings, "missing optional field: compliance (no framework citations)")
	}
	if ctl.Remediation == nil || ctl.Remediation.Action == "" {
		result.Warnings = append(result.Warnings, "missing remediation.action")
	}
	if ctl.AttackStage() == "" {
		result.Warnings = append(result.Warnings, "missing params.attack_stage")
	}

	// Prepare validation.
	if prepErr := ctl.Prepare(); prepErr != nil {
		result.Errors = append(result.Errors, "prepare error: "+prepErr.Error())
		return result
	}

	// CEL predicate validation — try compiling.
	if celEval != nil && ctl.Type == policy.TypeUnsafeState {
		// Create a minimal test asset to check compilation.
		testAsset := dummyAsset()
		_, evalErr := celEval(ctl, testAsset, nil)
		if evalErr != nil {
			errStr := evalErr.Error()
			if strings.Contains(errStr, "undeclared") || strings.Contains(errStr, "syntax") {
				result.Errors = append(result.Errors, "CEL error: "+errStr)
			}
			// Other eval errors (missing property) are expected with dummy asset.
		}
	}

	return result
}

func dummyAsset() asset.Asset {
	return asset.Asset{
		ID:         "lint-test-asset",
		Type:       "lint_test",
		Vendor:     "test",
		Properties: map[string]any{},
	}
}

func collectControlPaths(pathOrDir string) ([]string, error) {
	info, err := os.Stat(pathOrDir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", pathOrDir, err)
	}
	if !info.IsDir() {
		return []string{pathOrDir}, nil
	}

	var paths []string
	err = filepath.WalkDir(pathOrDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") && strings.HasPrefix(filepath.Base(p), "CTL.") {
			paths = append(paths, p)
		}
		return nil
	})
	return paths, err
}
