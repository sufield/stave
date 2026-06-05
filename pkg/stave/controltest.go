package stave

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

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
		// Single-file mode: the loader only scans directories, so
		// load the file's parent directory and narrow execution to
		// the requested control via the filter. The filter must be
		// the requested control's actual ID (matchFilter does an
		// exact ID match), so read it from the file rather than
		// guessing from the basename — without this the filter stays
		// empty and every sibling control in the directory runs too.
		idx := strings.LastIndex(cfg.ControlPath, "/")
		if idx >= 0 {
			dir = cfg.ControlPath[:idx]
		} else {
			dir = "."
		}
		id, err := controlIDFromFile(cfg.ControlPath)
		if err != nil {
			return nil, TestSummary{}, fmt.Errorf("resolve control ID from %q: %w", cfg.ControlPath, err)
		}
		filter = id
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

// controlIDFromFile reads only the `id` field of a control YAML file.
// Single-file mode uses it to derive an exact-match filter so that
// only the requested control runs, independent of any filename
// convention. A missing or empty id is an error: an empty filter
// would silently widen the run back to the whole parent directory,
// which is exactly the failure this guards against.
func controlIDFromFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is the caller-supplied control file under test (CLI/test input), not attacker-controlled
	if err != nil {
		return "", fmt.Errorf("read control file: %w", err)
	}
	var head struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(data, &head); err != nil {
		return "", fmt.Errorf("parse control YAML: %w", err)
	}
	if strings.TrimSpace(head.ID) == "" {
		return "", errors.New("control file has no id field")
	}
	return head.ID, nil
}

// ErrFailingTests signals that RunControlTests completed but one
// or more test cases produced a verdict that didn't match its
// expected verdict. The CLI exit-code shim maps this (and similar
// sentinels) to ExitViolations (3) so CI can fail the build
// without parsing the JSON output.
var ErrFailingTests = errors.New("control tests failed")
