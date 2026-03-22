package apply

import (
	"context"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
)

func (r *Runner) writeResults(ctx context.Context, cfg Config, result evaluation.Result) error {
	marshaler, err := r.Provider.NewFindingWriter(cfg.OutputFormat, cfg.IsJSONMode)
	if err != nil {
		return err
	}

	enricher := remediation.NewMapper(crypto.NewHasher())
	enrichFn := func(res evaluation.Result) (appcontracts.EnrichedResult, error) {
		return appeval.Enrich(enricher, cfg.Sanitizer, res)
	}

	return appeval.RunOutputPipeline(ctx, cfg.Stdout, result, marshaler, enrichFn, nil)
}

// finalizeProfileEvaluation reports warnings and returns the appropriate exit error.
func finalizeProfileEvaluation(stderr io.Writer, quiet bool, results evaluation.Result, snapshots []asset.Snapshot, ctlDir, inputFile string) error {
	unprovable := asset.CountUnprovablySafe(snapshots)
	if unprovable > 0 && !quiet {
		if _, err := fmt.Fprintf(stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", unprovable); err != nil {
			return err
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
			return err
		}
	}
	return nil
}
