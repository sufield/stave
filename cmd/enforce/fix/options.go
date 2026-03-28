package fix

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// fixOptions holds the raw CLI flag values for the fix command.
type fixOptions struct {
	InputPath  string
	FindingRef string
}

// BindFlags attaches the options to a Cobra command.
func (o *fixOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.InputPath, "input", "", "Path to evaluation JSON (required)")
	f.StringVar(&o.FindingRef, "finding", "", "Finding selector: <control_id>@<asset_id> (required)")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("finding")
}

// Prepare normalizes paths and validates inputs. Called from PreRunE.
func (o *fixOptions) Prepare(_ *cobra.Command) error {
	o.InputPath = fsutil.CleanUserPath(o.InputPath)
	if _, err := os.Stat(o.InputPath); err != nil {
		return &ui.UserError{
			Err: fmt.Errorf("--input file %s: %w", o.InputPath, err),
		}
	}
	return o.validateFindingRef()
}

func (o *fixOptions) validateFindingRef() error {
	parts := strings.SplitN(o.FindingRef, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return &ui.UserError{
			Err: fmt.Errorf("invalid --finding %q: must be <control_id>@<asset_id>", o.FindingRef),
		}
	}
	return nil
}
