// Package catalog implements `stave catalog` (and its alias
// `stave capabilities catalog`) — the user-facing catalog view that
// groups controls + chains + operational features by service and
// renders a browse-friendly listing. Subcommands: stats, inspect.
// Paired with `stave search` for query-by-intent.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	Service     string
	Category    string
	KindFilter  string
	Format      string
	ControlsDir string
	ChainsDir   string
	NoPager     bool
	Severity    string
	Taxonomy    string
	Leaf        bool
}

// NewCmd constructs the `catalog` command. Registered both as a
// top-level command (`stave catalog`) and as a subcommand of
// `capabilities` (`stave capabilities catalog`). Each call site
// must call NewCmd separately — Cobra cannot share instances.
func NewCmd() *cobra.Command {
	opts := &options{
		Format:      "auto",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Print the user-facing capability catalog",
		Long: `Catalog emits the grouped view of what Stave can check: control
groups by (service, category), compound chains, and operational
features (readiness, gaps, drift, validate, export-sir). Pair with
` + "`stave search <query>`" + ` to look up by intent.

Use --service to filter to one service (s3, iam, lambda, …) or
--category to filter within a service. --kind narrows to one of
control_group | chain | operational.

Output is paged through $PAGER (then 'less -R', then 'more') when stdout is a
terminal, and written plain and unpaged when stdout is a pipe, a redirect, or
CI — so '... | grep' and '... > file' are unaffected. JSON is never paged.
Use --no-pager to force plain output on a terminal.

Drill-down mirrors 'man <topic>':
  catalog                 summary: one line per service
  catalog <SERVICE>       that service's capabilities, one line each
  catalog <SERVICE> --leaf  the leaf controls (individual control IDs)
  catalog --severity CRITICAL  only the matching leaf controls, any level

--severity matches an EXACT level and lists control-group controls only;
chains and operational features carry no severity and are excluded (stated in
the output, not silently dropped). --leaf is the leaf drill-down: --controls/-i
is already the catalog directory, so the leaf toggle is a distinct flag.

Inputs:
  --service SVC    Filter to one service (e.g. s3); also accepted positionally
  --category CAT   Filter to one category within --service (e.g. public)
  --kind K         control_group | chain | operational
  --severity SEV   critical | high | medium | low | info (leaf controls)
  --leaf           Drill to individual leaf controls
  --format F       auto (default; paged on a TTY) | text | wide | json
  --no-pager       Never page, even on a terminal
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)

Exit codes:
  0   Success
  2   Invalid input
  4   Internal error
`,
		Example: `  stave catalog
  stave catalog s3
  stave catalog --service s3 --leaf
  stave catalog --kind chain
  stave catalog --format json | jq '.capabilities | length'
  stave catalog stats
  stave catalog inspect CTL.S3.PUBLIC.001
  stave catalog coverage
  stave catalog gaps checklist.yaml`,
		// Wrap the arg-count check in a UserError so a surplus positional
		// (e.g. `catalog s3 iam`) exits 2 (invalid input), not 4 (internal):
		// cobra's raw "accepts at most 1 arg(s)" error isn't unknown-command-
		// shaped, so without this it falls through ExitCode() to ExitInternal.
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return &ui.UserError{Err: err}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Positional SERVICE is accepted as an alias for --service so the
			// drill-down reads like `man <topic>`. An explicit --service wins.
			if len(args) == 1 && opts.Service == "" {
				opts.Service = args[0]
			}
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Service, "service", "", "filter to one service")
	cmd.Flags().StringVar(&opts.Category, "category", "", "filter to one category (requires --service)")
	cmd.Flags().StringVar(&opts.KindFilter, "kind", "", "filter to one kind: control_group | chain | operational")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "auto", "output format: auto | text | wide | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().StringVar(&opts.Severity, "severity", "", "show only leaf controls of this severity: critical | high | medium | low | info")
	cmd.Flags().StringVar(&opts.Taxonomy, "taxonomy", "", "filter by taxonomy category (comma-separated, OR-joined)")
	cmd.Flags().BoolVar(&opts.Leaf, "leaf", false, "drill to leaf controls (the individual control IDs); pairs with a service")
	cmd.AddCommand(newStatsCmd())
	cmd.AddCommand(newInspectCmd())
	cmd.AddCommand(newCoverageCmd())
	cmd.AddCommand(newGapsCmd())
	cmd.AddCommand(newTaxonomyCmd())
	cmd.AddCommand(newMatrixCmd())
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	// Validate the format up front (guard, not a render dispatch — the
	// rendering lives in pkg/stave — so this does not trip the
	// inline-format-switch lint).
	if opts.Format != "json" && opts.Format != "wide" && opts.Format != "text" && opts.Format != "auto" && opts.Format != "" {
		return &ui.UserError{Err: fmt.Errorf("--format must be text | auto | wide | json (got %q)", opts.Format)}
	}

	out, err := stave.RenderCatalog(ctx, stave.CatalogOptions{
		Service:     opts.Service,
		Category:    opts.Category,
		KindFilter:  opts.KindFilter,
		Format:      opts.Format,
		ControlsDir: opts.ControlsDir,
		ChainsDir:   opts.ChainsDir,
		Severity:    opts.Severity,
		Taxonomy:    opts.Taxonomy,
		Leaf:        opts.Leaf,
	})
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"render catalog"); preserve exit 4.
	}

	// Page human output on a TTY; never page JSON, never when --no-pager is
	// set or stdout is not a terminal. NewPager returns w unchanged with a
	// no-op close in the unpaged cases, so piped/redirected output is
	// byte-for-byte identical.
	pageable := opts.Format != "json" && !opts.NoPager
	pw, closePager := ui.NewPager(ctx, w, pageable)
	_, writeErr := pw.Write(out)
	closeErr := closePager()
	if writeErr != nil {
		return fmt.Errorf("write catalog: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr //nolint:wrapcheck // already wrapped ("wait for pager: …") by NewPager's closer.
	}
	return nil
}
