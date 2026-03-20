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
	Provider *compose.Provider
}

// NewExplainer creates an Explainer with the given provider.
func NewExplainer(p *compose.Provider) *Explainer {
	return &Explainer{Provider: p}
}

// Run executes the explain workflow.
func (e *Explainer) Run(ctx context.Context, req ExplainRequest) error {
	id := strings.TrimSpace(req.ControlID)
	if id == "" {
		return &ui.UserError{Err: fmt.Errorf("control id cannot be empty")}
	}

	finder := &composeFinder{provider: e.Provider}
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

// composeFinder adapts compose.LoadControlByID to the ControlFinder interface.
type composeFinder struct {
	provider *compose.Provider
}

func (f *composeFinder) FindByID(ctx context.Context, dir, id string) (policy.ControlDefinition, error) {
	ctl, err := compose.LoadControlByID(ctx, f.provider, dir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave validate --controls %s", dir))
	}
	return ctl, nil
}

// NewExplainCmd constructs the explain command.
func NewExplainCmd(p *compose.Provider) *cobra.Command {
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
			explainer := NewExplainer(p)
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
