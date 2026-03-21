package apply

import (
	"context"
	"fmt"

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

func (r *Runner) finalize(cfg Config, results evaluation.Result, snapshots []asset.Snapshot, ctlDir string) error {
	unprovable := asset.CountUnprovablySafe(snapshots)
	if unprovable > 0 && !cfg.Quiet {
		fmt.Fprintf(cfg.Stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", unprovable)
	}

	if len(results.Findings) > 0 {
		if !cfg.Quiet {
			ui.WriteHint(cfg.Stderr, fmt.Sprintf("stave diagnose --controls %s --observations %s", ctlDir, cfg.InputFile))
		}
		return ui.ErrViolationsFound
	}

	if !cfg.Quiet {
		fmt.Fprintln(cfg.Stderr, "Evaluation complete. No violations found.")
	}
	return nil
}
