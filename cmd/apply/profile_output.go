package apply

import (
	"context"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func (r *Runner) writeResults(ctx context.Context, cfg Config, result *evaluation.ComplianceReport, controls []policy.ControlDefinition) error {
	marshaler, err := r.newFindingWriter(cfg.OutputFormat, false)
	if err != nil {
		return err
	}

	enricher := remediation.NewPlanner()
	enrichFn := func(res *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
		return appeval.Enrich(enricher, cfg.Sanitizer, res)
	}

	pipeline := &appeval.OutputPipeline{
		Marshaler:       marshaler,
		Enricher:        enrichFn,
		CoveragePosture: buildCoveragePosture(controls, nil),
	}
	if err := pipeline.Run(ctx, cfg.Stdout, result); err != nil {
		return fmt.Errorf("run output pipeline: %w", err)
	}
	return nil
}

// finalizeProfileEvaluation reports warnings and returns the appropriate exit error.
func finalizeProfileEvaluation(stderr io.Writer, quiet bool, results *evaluation.ComplianceReport, snapshots []asset.Snapshot, ctlDir, inputFile string) error {
	unprovable := asset.CountUnprovablySafe(snapshots)
	if unprovable > 0 && !quiet {
		if _, err := fmt.Fprintf(stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", unprovable); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}

	if len(results.Findings) > 0 {
		if !quiet {
			ui.WriteHint(stderr, fmt.Sprintf("stave diagnose --controls %s --observations %s", ctlDir, inputFile))
		}
		return ui.ErrViolationsFound
	}

	if !quiet {
		if _, err := fmt.Fprintln(stderr, "Evaluation complete. No violations found."); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}
