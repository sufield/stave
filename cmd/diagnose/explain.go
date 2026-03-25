package diagnose

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/output/text"
	appexplain "github.com/sufield/stave/internal/app/explain"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// ExplainRequest holds the inputs for the explain workflow.
type ExplainRequest struct {
	ControlID   string
	ControlsDir string
	Format      ui.OutputFormat
	Stdout      io.Writer
}

// Explainer analyzes a control and explains its predicate structure.
type Explainer struct {
	NewCtlRepo compose.CtlRepoFactory
}

// NewExplainer creates an Explainer with the given control repo factory.
func NewExplainer(newCtlRepo compose.CtlRepoFactory) *Explainer {
	return &Explainer{NewCtlRepo: newCtlRepo}
}

// Run executes the explain workflow.
func (e *Explainer) Run(ctx context.Context, req ExplainRequest) error {
	id := strings.TrimSpace(req.ControlID)
	if id == "" {
		return &ui.UserError{Err: fmt.Errorf("control id cannot be empty")}
	}

	finder := &composeFinder{newCtlRepo: e.NewCtlRepo}
	runner := &appexplain.Explainer{Finder: finder}
	result, err := runner.Run(ctx, appexplain.ExplainInput{
		ControlID:   req.ControlID,
		ControlsDir: req.ControlsDir,
	})
	if err != nil {
		return err
	}

	if req.Format.IsJSON() {
		return jsonutil.WriteIndented(req.Stdout, result)
	}
	return text.WriteExplainText(req.Stdout, result)
}

// composeFinder implements the ControlFinder interface using a control repository factory.
type composeFinder struct {
	newCtlRepo compose.CtlRepoFactory
}

func (f *composeFinder) FindByID(ctx context.Context, dir, id string) (policy.ControlDefinition, error) {
	repo, err := f.newCtlRepo()
	if err != nil {
		return policy.ControlDefinition{}, err
	}
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("loading controls from %s: %w", dir, err)
	}
	for _, c := range controls {
		if c.ID.String() == id {
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

Examples:
  stave explain CTL.S3.PUBLIC.001
  stave explain CTL.S3.PUBLIC.001 --controls ./controls
  stave explain CTL.S3.PUBLIC.001 --format json` + metadata.OfflineHelpSuffix,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}
			explainer := NewExplainer(newCtlRepo)
			return explainer.Run(cmd.Context(), ExplainRequest{
				ControlID:   args[0],
				ControlsDir: controlsDir,
				Format:      fmtValue,
				Stdout:      cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&controlsDir, "controls", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
