package stave

import (
	"context"
	"errors"
	"fmt"
	"strings"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/app/controltest"
)

// TestResult is the outcome of running all embedded test cases on
// one control. Aliased from internal/app/controltest so cmd/test and
// any library caller see the same JSON shape (`stave test --format json`
// output is a public artifact).
type TestResult = controltest.Result

// TestCaseResult is the outcome of a single test case inside a
// control. Aliased so renderers don't reach into the internal
// scorer package.
type TestCaseResult = controltest.CaseResult

// TestSummary holds the aggregate counts across all tested controls.
type TestSummary = controltest.Summary

// TestConfig parameterizes a [RunControlTests] call. ControlsDir
// is the directory of control YAML files; ControlPath optionally
// narrows to a single file (its parent directory becomes
// ControlsDir and Filter is derived from the file's control ID).
// Filter is a plain substring match on control IDs. FailFast aborts
// the run on the first case failure.
type TestConfig struct {
	ControlsDir string
	ControlPath string
	Filter      string
	FailFast    bool
}

// RunControlTests loads controls from disk, builds a CEL evaluator,
// and executes every embedded test case. Returns the per-control
// results and the aggregate summary.
//
// Mirrors what cmd/test used to orchestrate manually with
// internal/app/controltest + internal/adapters/cel +
// internal/adapters/controls/yaml + internal/adapters/predicate.
// Encapsulating the wiring here lets cmd/test stay at the facade
// bar — flag binding + one library call + output formatting.
//
// Returns [ErrFailingTests] in the error result when summary.Failed
// > 0 so the CLI's exit-code shim maps to ExitViolations (3) for
// CI-friendly failure semantics without the caller poking at the
// summary numerics.
func RunControlTests(ctx context.Context, cfg TestConfig) ([]TestResult, TestSummary, error) {
	dir := cfg.ControlsDir
	filter := cfg.Filter
	if cfg.ControlPath != "" {
		// Single-file mode: load the parent directory and narrow
		// via filter to the single file's basename (the loader
		// scans a directory; we use the filter as the slice).
		idx := strings.LastIndex(cfg.ControlPath, "/")
		if idx >= 0 {
			dir = cfg.ControlPath[:idx]
		} else {
			dir = "."
		}
	}

	loader := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc()))
	controls, err := loader.LoadControls(ctx, dir)
	if err != nil {
		return nil, TestSummary{}, fmt.Errorf("load controls: %w", err)
	}

	eval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, TestSummary{}, fmt.Errorf("init CEL evaluator: %w", err)
	}

	results, summary := controltest.Run(controltest.RunInput{
		Controls:  controls,
		Evaluator: eval,
		Filter:    filter,
		FailFast:  cfg.FailFast,
	})

	if summary.Failed > 0 {
		return results, summary, ErrFailingTests
	}
	return results, summary, nil
}

// ErrFailingTests signals that RunControlTests completed but one
// or more test cases produced a verdict that didn't match its
// expected verdict. The CLI exit-code shim maps this (and similar
// sentinels) to ExitViolations (3) so CI can fail the build
// without parsing the JSON output.
var ErrFailingTests = errors.New("control tests failed")
