//go:build stavedev

package artifacts

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/lint"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewLintCmd constructs the lint command.
func NewLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <path>",
		Short: "Lint control files for design quality",
		Long: `Lint checks control design quality rules independent of schema validity.
It is deterministic, offline, and file-based.

Rules:
  - ID namespace format
  - Required metadata (name/description/remediation)
  - Determinism key constraints
  - Stable ordering hints for list-like sections` + metadata.OfflineHelpSuffix,
		Args:          cobra.ExactArgs(1),
		RunE:          runLint,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runLint(cmd *cobra.Command, args []string) error {
	target := fsutil.CleanUserPath(args[0])
	files, err := collectYAMLFiles(target)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no control YAML files found in %s", target)
	}

	linter := lint.NewLinter()
	var all []lint.Diagnostic

	for _, file := range files {
		data, readErr := fsutil.ReadFileLimited(file)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", file, readErr)
		}
		all = append(all, linter.LintBytes(file, data)...)
	}

	slices.SortFunc(all, compareDiagnostic)

	errorCount := 0
	out := cmd.OutOrStdout()
	for _, d := range all {
		if d.Severity == lint.SeverityError {
			errorCount++
		}
		if _, err = fmt.Fprintf(out, "%s:%d:%d  %s  %s\n", d.Path, d.Line, d.Col, d.RuleID, d.Message); err != nil {
			return err
		}
	}

	if errorCount > 0 {
		return ui.ErrValidationFailed
	}
	return nil
}

func compareDiagnostic(a, b lint.Diagnostic) int {
	if c := strings.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if a.Line != b.Line {
		return a.Line - b.Line
	}
	if a.Col != b.Col {
		return a.Col - b.Col
	}
	if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	return strings.Compare(a.Message, b.Message)
}

func collectYAMLFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(root))
		if ext == ".yaml" || ext == ".yml" {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("unsupported file type %q", root)
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}
