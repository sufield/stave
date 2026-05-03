package forge

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
)

func newPreviewCmd() *cobra.Command {
	var snapshot, predicateExpr, assetType, field, op, value string

	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Evaluate a predicate against a snapshot without writing files",
		Long: `Evaluates a control predicate against all matching assets in a snapshot
and shows per-resource FAIL/PASS results. Uses the identical CEL
evaluation path as stave apply.

Predicate can be specified as field/op/value or as a raw expression.

Exit Codes:
  0   Preview completed successfully
  2   Invalid input or missing flags
  4   Internal error

Examples:
  stave forge preview --snapshot obs.json \
    --field properties.storage.access.public_read --op eq --value true

  stave forge preview --snapshot obs.json --asset-type aws_s3_bucket \
    --field properties.storage.encryption.at_rest_enabled --op eq --value false`,
		Example:       `  stave forge preview --snapshot obs.json --field properties.storage.access.public_read --op eq --value true`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPreview(cmd.OutOrStdout(), snapshot, assetType, field, op, value, predicateExpr)
		},
	}

	cmd.Flags().StringVar(&snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "filter to a specific asset type")
	cmd.Flags().StringVar(&field, "field", "", "predicate field path")
	cmd.Flags().StringVar(&op, "op", "eq", "predicate operator")
	cmd.Flags().StringVar(&value, "value", "true", "predicate value")
	cmd.Flags().StringVar(&predicateExpr, "predicate", "", "raw CEL predicate expression (alternative to field/op/value)")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

func runPreview(w io.Writer, snapshotPath, assetType, field, op, value, predicateExpr string) error {
	if field == "" && predicateExpr == "" {
		return errors.New("either --field or --predicate is required")
	}

	snapshots, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return errors.New("snapshot file contains no observations")
	}
	snap := &snapshots[len(snapshots)-1]

	// Build a synthetic control definition for evaluation.
	ctl := policy.ControlDefinition{
		DSLVersion: "ctrl.v1",
		ID:         kernel.ControlID("CTL.FORGE.PREVIEW.000"),
		Name:       "Forge Preview",
		Type:       policy.TypeUnsafeState,
	}

	if field != "" {
		ctl.UnsafePredicate = policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath(field),
				Op:    predicate.Operator(op),
				Value: policy.NewOperand(parseValue(value)),
			}},
		}
	}

	// Create CEL evaluator.
	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return fmt.Errorf("init CEL evaluator: %w", err)
	}

	// Prepare the control for evaluation.
	if err := ctl.Prepare(); err != nil {
		return fmt.Errorf("prepare control: %w", err)
	}

	// Evaluate against matching assets.
	var failCount, passCount, errCount int
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if assetType != "" && string(a.Type) != assetType {
			continue
		}

		unsafe, evalErr := celEval(ctl, *a, nil)
		if evalErr != nil {
			fmt.Fprintf(w, "  ERROR  %s  %v\n", a.ID, evalErr)
			errCount++
			continue
		}

		if unsafe {
			fmt.Fprintf(w, "  FAIL   %s\n", a.ID)
			failCount++
		} else {
			fmt.Fprintf(w, "  PASS   %s\n", a.ID)
			passCount++
		}
	}

	fmt.Fprintf(w, "\n%d FAIL  |  %d PASS  |  %d ERROR\n", failCount, passCount, errCount)
	return nil
}

// parseValue converts a string flag value to its typed equivalent.
func parseValue(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	return s
}
