package diagnose

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appexplain "github.com/sufield/stave/internal/app/explain"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"

	"github.com/sufield/stave/internal/adapters/output/text"
)

// ExplainRequest holds the inputs for the explain workflow.
type ExplainRequest struct {
	ControlID   kernel.ControlID
	ControlsDir string
}

// Explainer analyzes a control and explains its predicate structure.
type Explainer struct {
	Finder appexplain.ControlFinder
}

// Run executes the explain workflow and returns the result.
// Presentation is handled by the caller.
func (e *Explainer) Run(ctx context.Context, req ExplainRequest) (appexplain.ExplainResult, error) {
	if req.ControlID == "" {
		return appexplain.ExplainResult{}, &ui.UserError{Err: fmt.Errorf("control id cannot be empty")}
	}

	runner := &appexplain.Explainer{Finder: e.Finder}
	return runner.Run(ctx, appexplain.ExplainInput{
		ControlID:   req.ControlID,
		ControlsDir: req.ControlsDir,
	})
}

// NewExplainerWithFinder creates an Explainer from an initialized repository.
func NewExplainerWithFinder(repo appcontracts.ControlRepository) *Explainer {
	return &Explainer{Finder: &repoFinder{repo: repo}}
}

// WriteExplainResult renders an ExplainResult to the writer in the given format.
func WriteExplainResult(w io.Writer, result appexplain.ExplainResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, result)
	}
	return text.WriteExplainText(w, result)
}

// repoFinder implements appexplain.ControlFinder using an initialized repo.
// The repo is created once in the CLI layer and reused for all lookups.
type repoFinder struct {
	repo appcontracts.ControlRepository
}

func (f *repoFinder) FindByID(ctx context.Context, dir string, id kernel.ControlID) (policy.ControlDefinition, error) {
	controls, err := f.repo.LoadControls(ctx, dir)
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("loading controls from %s: %w", dir, err)
	}
	for _, c := range controls {
		if c.ID == id {
			return c, nil
		}
	}
	return policy.ControlDefinition{}, ui.WithNextCommand(
		fmt.Errorf("%w: %q in %s", compose.ErrControlNotFound, id, dir),
		fmt.Sprintf("stave validate --controls %s", dir))
}

// NewExplainCmd constructs the explain command.
func NewExplainCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	var (
		controlsDir string
		format      string
	)

	cmd := &cobra.Command{
		Use:   "explain <control-id>",
		Short: "Explain how a control evaluates and which fields it needs",
		Long: `Explain loads a single control and prints:
  - matched field paths used by predicates
  - operator/value expectations
  - a minimal obs.v0.1 snippet you can start from

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example:       `  stave explain --controls controls/s3 --format json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}

			repo, err := newCtlRepo()
			if err != nil {
				return fmt.Errorf("create control loader: %w", err)
			}

			explainer := &Explainer{Finder: &repoFinder{repo: repo}}
			result, err := explainer.Run(cmd.Context(), ExplainRequest{
				ControlID:   kernel.ControlID(args[0]),
				ControlsDir: controlsDir,
			})
			if err != nil {
				return err
			}
			return WriteExplainResult(cmd.OutOrStdout(), result, fmtValue)
		},
	}

	cmd.Flags().StringVar(&controlsDir, "controls", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
