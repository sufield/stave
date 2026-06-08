// Package expand implements the `stave expand` command, which surfaces
// every control sharing a structural defect archetype with a given finding
// (or with a directly-specified archetype). The command is read-only:
// it loads the control catalog and groups it by archetype.
package expand

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	Archetype   string
	Finding     string
	List        bool
	Format      string
	Snapshots   string
	ControlsDir string
	NoPager     bool
}

// NewCmd constructs the expand command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "expand",
		Short: "Show every control sharing a structural defect archetype",
		Long: `Expand a finding or archetype into the family of controls that
detect the same class of structural defect across services.

When a single finding fires, its archetype identifies every other place
the same defect can manifest in your infrastructure. Use --finding to
pivot from a specific control, --archetype to start from a known class,
or --list to see all archetypes.

Inputs:
  --archetype <id>     Archetype ID (e.g., ghost-reference)
  --finding <id>       Control ID to look up the archetype from
  --list               List all archetypes with control counts
  --format text|json   Output format (default: text)
  --snapshots <dir>    Path to observations dir (optional; enables
                       snapshot coverage section)
  --controls <dir>     Control definitions directory (default: controls)

Outputs:
  stdout: archetype summary, controls grouped by service, optional
          snapshot coverage and recommended commands.
  stderr: errors only.

Exit codes:
  0   success
  2   input error (missing flags, unknown archetype/finding)
  4   internal error (control loader failure)
  130 SIGINT
`,
		Example: `  # List all archetypes with control counts
  stave expand --list

  # Expand an archetype into its control family
  stave expand --archetype ghost-reference

  # Pivot from a known finding to its sibling controls
  stave expand --finding CTL.ROUTE53.DANGLING.S3.001

  # JSON output for tooling
  stave expand --archetype ghost-reference --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := runExpand(cmd.Context(), pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.Archetype, "archetype", "", "archetype ID to expand (e.g., ghost-reference)")
	flags.StringVar(&opts.Finding, "finding", "", "control ID to expand from (e.g., CTL.ROUTE53.DANGLING.S3.001)")
	flags.BoolVar(&opts.List, "list", false, "list all archetypes with control counts")
	flags.StringVarP(&opts.Format, "format", "f", "text", "output format: text or json")
	flags.BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	flags.StringVar(&opts.Snapshots, "snapshots", "", "observations directory for snapshot coverage check")
	flags.StringVarP(&opts.ControlsDir, cliflags.FlagControls, "i", "controls", "control definitions directory")

	cmd.MarkFlagsMutuallyExclusive("archetype", "finding", "list")

	return cmd
}

func runExpand(ctx context.Context, w io.Writer, opts *options) error {
	if opts.Archetype == "" && opts.Finding == "" && !opts.List {
		return inputErrorf("one of --archetype, --finding, or --list is required")
	}
	if opts.Format != "text" && opts.Format != "json" {
		return inputErrorf("--format must be text or json (got %q)", opts.Format)
	}

	var out []byte
	var err error
	if opts.List {
		out, err = stave.ExpandList(ctx, opts.ControlsDir, opts.Format)
	} else {
		out, err = stave.ExpandArchetype(ctx, opts.ControlsDir, opts.Archetype, opts.Finding, opts.Snapshots, opts.Format)
	}
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"render expansion"); preserve exit 4.
	}
	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write expansion: %w", werr)
	}
	return nil
}

// inputErrorf wraps a user-input error so the executor maps it to exit
// code 2 (missing flags, unknown archetype/finding).
func inputErrorf(format string, args ...any) error {
	return &ui.UserError{Err: fmt.Errorf(format, args...)}
}
