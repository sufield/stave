package compliance

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/compliancemapping"
	"github.com/sufield/stave/pkg/stave"
)

// evalOutput is the minimal slice of the out.v0.1 evaluation JSON this command
// needs: the control ID behind each finding. A control ID present here means
// that Stave control produced a violation on the snapshot.
type evalOutput struct {
	Findings []struct {
		ControlID string `json:"control_id"`
	} `json:"findings"`
}

// run evaluates the snapshot against the framework mapping and renders the
// three-list coverage report. Thin: load mapping → run the existing evaluation
// pipeline → fold findings into the mapping → render.
func run(cmd *cobra.Command, opts *options) error {
	mapping, err := compliancemapping.Load(opts.framework)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	req := stave.StandardRequest{
		ObservationsDir: opts.snapshot,
		ControlsDir:     opts.controls,
		ControlsFlagSet: opts.controlsSet,
		UseBuiltin:      !opts.controlsSet, // default: verify against the built-in catalog
		Format:          "json",
		Now:             opts.now,
		// ponytail: the engine requires a duration; SLA breaches are risk_signals,
		// not control findings, so they don't affect compliance buckets.
		MaxUnsafe: "168h",
	}
	if opts.snapshot == "-" {
		req.Stdin = cmd.InOrStdin()
	}

	res, err := stave.EvaluateStandard(cmd.Context(), req)
	if err != nil {
		// %w preserves the facade's sentinels (ErrInvalidInput→exit 2, etc.).
		return fmt.Errorf("evaluate snapshot: %w", err)
	}

	var out evalOutput
	if jerr := json.Unmarshal(res.Output, &out); jerr != nil {
		return fmt.Errorf("parse evaluation output: %w", jerr)
	}
	violated := make(map[string]bool, len(out.Findings))
	for _, f := range out.Findings {
		violated[f.ControlID] = true
	}

	report := mapping.Evaluate(violated)

	renderer, err := NewRenderer(opts.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := renderer.Render(cmd.OutOrStdout(), &report); err != nil {
		return fmt.Errorf("render compliance report: %w", err)
	}

	// A failed covered control is a finding: exit 3 (evaluation completed with
	// findings), consistent with `apply`. Gaps/out-of-scope never gate.
	if report.HasFailures() {
		return ui.ErrViolationsFound
	}
	return nil
}
