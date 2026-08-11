package forgecmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type lintResult struct {
	ControlID string   `json:"control_id"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Infos     []string `json:"infos,omitempty"`
}

// Lint runs static analysis over a control YAML file or directory and returns
// the report. When errors exist (or strict + warnings exist) it also returns a
// non-nil gating error (the command maps it to exit 4; the report is still
// rendered). It is the library entry point behind `stave forge lint`.
func Lint(controlPath string, semantic, strict bool) ([]byte, error) {
	return LintWithFormat(controlPath, semantic, strict, "text")
}

// LintWithFormat is Lint with configurable output format ("text" or "json").
func LintWithFormat(controlPath string, semantic, strict bool, format string) ([]byte, error) {
	paths, err := collectControlPaths(controlPath)
	if err != nil {
		return nil, err
	}

	celEval, celErr := stavecel.NewPredicateEval()
	if celErr != nil {
		return nil, fmt.Errorf("init CEL: %w", celErr)
	}

	results := make([]lintResult, 0, len(paths))
	totalErrors := 0
	totalWarnings := 0

	for _, p := range paths {
		result := lintControl(p, celEval, semantic)
		totalErrors += len(result.Errors)
		totalWarnings += len(result.Warnings)
		results = append(results, result)
	}

	var buf bytes.Buffer
	if format == "json" {
		type jsonOutput struct {
			Results  []lintResult `json:"results"`
			Errors   int          `json:"errors"`
			Warnings int          `json:"warnings"`
			Files    int          `json:"files"`
		}
		out := jsonOutput{Results: results, Errors: totalErrors, Warnings: totalWarnings, Files: len(paths)}
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(out); encErr != nil {
			return nil, fmt.Errorf("encode lint JSON: %w", encErr)
		}
	} else {
		for _, result := range results {
			if len(result.Errors)+len(result.Warnings)+len(result.Infos) == 0 {
				continue
			}
			fmt.Fprintf(&buf, "%s\n", result.ControlID)
			for _, e := range result.Errors {
				fmt.Fprintf(&buf, "  ERROR   %s\n", e)
			}
			for _, wn := range result.Warnings {
				fmt.Fprintf(&buf, "  WARNING %s\n", wn)
			}
			for _, info := range result.Infos {
				fmt.Fprintf(&buf, "  INFO    %s\n", info)
			}
			fmt.Fprintln(&buf)
		}
		fmt.Fprintf(&buf, "%d error(s), %d warning(s) across %d file(s)\n",
			totalErrors, totalWarnings, len(paths))
	}

	if totalErrors > 0 {
		return buf.Bytes(), fmt.Errorf("%d lint error(s)", totalErrors)
	}
	if strict && totalWarnings > 0 {
		return buf.Bytes(), fmt.Errorf("%d lint warning(s) (--strict mode)", totalWarnings)
	}
	return buf.Bytes(), nil
}

func lintControl(path string, celEval policy.PredicateEval, semantic bool) lintResult {
	result := lintResult{ControlID: filepath.Base(path)}

	data, err := fsutil.ReadFileLimited(fsutil.CleanUserPath(path))
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

	for _, issue := range ctl.Validate() {
		switch {
		case issue.IsError():
			result.Errors = append(result.Errors, issue.Message)
		case issue.IsWarning():
			result.Warnings = append(result.Warnings, issue.Message)
		}
	}
	result.Warnings = append(result.Warnings, ctl.CheckQuality().Warnings...)

	if prepErr := ctl.Prepare(); prepErr != nil {
		result.Errors = append(result.Errors, "prepare error: "+prepErr.Error())
		return result
	}

	if celEval != nil && ctl.RequiresCELValidation() {
		testAsset := dummyAsset()
		isUnsafe, evalErr := celEval(&ctl, testAsset, nil)
		if evalErr != nil {
			errStr := evalErr.Error()
			if strings.Contains(errStr, "undeclared") || strings.Contains(errStr, "syntax") {
				result.Errors = append(result.Errors, "CEL error: "+errStr)
			}
		} else if semantic && isUnsafe {
			result.Errors = append(result.Errors,
				"predicate may be always-firing: evaluates to VIOLATION on an empty asset with no properties")
		}
	}

	if len(ctl.Tests) == 0 {
		result.Warnings = append(result.Warnings, "no embedded test cases")
	}

	stage := ctl.AttackStage()
	if stage != "" {
		valid := slices.Contains(risk.AttackStages(), stage)
		if !valid {
			result.Errors = append(result.Errors,
				fmt.Sprintf("attack_stage %q is not a valid stage", stage))
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
	pathOrDir = fsutil.CleanUserPath(pathOrDir)
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
	if err != nil {
		return nil, fmt.Errorf("walk controls: %w", err)
	}
	return paths, nil
}
