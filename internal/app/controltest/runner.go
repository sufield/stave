// Package controltest runs embedded test cases from control YAML files
// using the same CEL evaluation path as stave apply.
package controltest

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Result is the outcome of running all tests in a control.
type Result struct {
	ControlID string       `json:"control_id"`
	TestCount int          `json:"test_count"`
	Passed    int          `json:"passed"`
	Failed    int          `json:"failed"`
	Cases     []CaseResult `json:"cases"`
}

// CaseResult is the outcome of a single test case.
type CaseResult struct {
	Name            string `json:"name"`
	ExpectedVerdict string `json:"expected_verdict"`
	ActualVerdict   string `json:"actual_verdict"`
	Passed          bool   `json:"passed"`
	Diagnosis       string `json:"diagnosis,omitempty"`
	Hint            string `json:"hint,omitempty"`
}

// IsPassing reports whether the case matched its expected verdict.
// Centralised so cmd/test renderers stop reading the raw Passed
// field — a future schema change (e.g. moving to a tri-state
// outcome enum) lands one place.
func (c *CaseResult) IsPassing() bool {
	return c != nil && c.Passed
}

// Summary holds aggregate test results.
type Summary struct {
	ControlsTested int `json:"controls_tested"`
	TotalCases     int `json:"total_cases"`
	Passed         int `json:"passed"`
	Failed         int `json:"failed"`
	Skipped        int `json:"skipped"`
}

// RunInput holds the inputs for a test run.
type RunInput struct {
	Controls  []policy.ControlDefinition
	Evaluator policy.PredicateEval
	Filter    string
	FailFast  bool
}

// Run executes all embedded test cases across all controls.
func Run(input RunInput) ([]Result, Summary) {
	var results []Result
	var summary Summary

	for i := range input.Controls {
		ctl := &input.Controls[i]
		if len(ctl.Tests) == 0 {
			continue
		}
		if input.Filter != "" && !matchFilter(string(ctl.ID), input.Filter) {
			continue
		}

		result := runControl(ctl, input.Evaluator)
		summary.ControlsTested++
		summary.TotalCases += result.TestCount
		summary.Passed += result.Passed
		summary.Failed += result.Failed
		results = append(results, result)

		if input.FailFast && result.Failed > 0 {
			break
		}
	}

	return results, summary
}

func runControl(ctl *policy.ControlDefinition, eval policy.PredicateEval) Result {
	result := Result{
		ControlID: string(ctl.ID),
		TestCount: len(ctl.Tests),
	}

	for _, tc := range ctl.Tests {
		cr := runCase(ctl, &tc, eval)
		if cr.Passed {
			result.Passed++
		} else {
			result.Failed++
		}
		result.Cases = append(result.Cases, cr)
	}

	return result
}

func runCase(ctl *policy.ControlDefinition, tc *policy.ControlTest, eval policy.PredicateEval) CaseResult {
	cr := CaseResult{
		Name:            tc.Name,
		ExpectedVerdict: strings.ToUpper(strings.TrimSpace(tc.Verdict)),
	}

	// Build asset from test case.
	a := asset.Asset{
		ID:         asset.ID(tc.Asset.AssetID),
		Type:       kernel.AssetType(tc.Asset.AssetType),
		Vendor:     kernel.Vendor(tc.Asset.Vendor),
		Properties: tc.Asset.Properties,
	}
	if a.Properties == nil {
		a.Properties = make(map[string]any)
	}

	// Call the SAME evaluation path as stave apply.
	unsafe, err := eval(ctl, a, nil)

	var actualVerdict string
	switch {
	case err != nil:
		actualVerdict = "INCONCLUSIVE"
	case unsafe:
		actualVerdict = "VIOLATION"
	default:
		actualVerdict = "PASS"
	}

	cr.ActualVerdict = actualVerdict
	cr.Passed = strings.EqualFold(cr.ExpectedVerdict, actualVerdict)

	if !cr.Passed {
		cr.Diagnosis, cr.Hint = diagnose(cr.ExpectedVerdict, actualVerdict, err)
	}

	return cr
}

func diagnose(expected, actual string, evalErr error) (string, string) {
	switch {
	case expected == "PASS" && actual == "VIOLATION":
		return "predicate_logic_error", "Predicate evaluated to unsafe — check property values match expected safe state"
	case expected == "VIOLATION" && actual == "PASS":
		return "predicate_logic_error", "Predicate evaluated to safe — check if comparison operators are inverted"
	case expected == "INCONCLUSIVE" && actual == "PASS":
		return "silent_risk", "Missing field produced PASS instead of INCONCLUSIVE — add has() guard to predicate"
	case expected == "INCONCLUSIVE" && actual == "VIOLATION":
		return "unexpected_violation", "Missing field produced VIOLATION — check isMissing behavior"
	case expected == "PASS" && actual == "INCONCLUSIVE":
		if evalErr != nil {
			return "missing_property", fmt.Sprintf("CEL error: %v — add missing field to test asset properties", evalErr)
		}
		return "missing_property", "Required field missing from test asset — add it to properties"
	case expected == "VIOLATION" && actual == "INCONCLUSIVE":
		return "missing_property", "Field missing prevented violation detection — add field to test asset"
	default:
		return "unknown", ""
	}
}

func matchFilter(controlID, filter string) bool {
	// Support glob-like patterns: CTL.S3.* matches CTL.S3.PUBLIC.001
	if before, ok := strings.CutSuffix(filter, "*"); ok {
		prefix := before
		return strings.HasPrefix(controlID, prefix)
	}
	return controlID == filter
}
