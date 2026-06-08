// Package search implements `stave search <query>` — keyword-and-
// synonym ranking over the capability catalog. The catalog
// aggregates controls + chains + operational features into
// ~150-200 capability records; the search command turns user intent
// ("public S3 bucket", "expired keys", "how long was this wrong")
// into matching catalog entries.
package search

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	Query       string
	Top         int
	Format      string
	ControlsDir string
	ChainsDir   string
}

// NewCmd constructs the `search` command.
func NewCmd() *cobra.Command {
	opts := &options{
		Top:         10,
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Find catalog entries matching a free-form intent",
		Long: `Search the capability catalog by intent. Ranks every capability
(control group, compound chain, operational feature) against the
query tokens, expanding synonyms so the user does not need to know
Stave's vocabulary first.

Scoring (per matched token, summed):
  title:        3
  use_when:     2
  keyword:      1
  description:  0.5
Phrase-verbatim hits add 5; threshold of 1.0 filters single-word
matches against long descriptions.

Use this when you know your problem but not the catalog vocabulary:
"public S3 bucket", "expired access keys", "Cognito unauthenticated
access", "CloudTrail logging disabled", "shadow admin", "orphaned
policies".

Inputs:
  <query>       Free-form intent string (required)
  --top N       Number of matches to surface (default 10)
  --format F    text (default) | json
  --controls    Control catalog directory (default: controls)
  --chains      Chain catalog directory (default: chains)

Exit codes:
  0   Matches found (or zero matches but query was well-formed)
  2   Invalid input (missing query, bad --format)
  4   Internal error (catalog load failure)
`,
		Example: `  stave search "public S3 bucket"
  stave search "how long was this misconfigured"
  stave search "shadow admin"
  stave search "kms rotation" --format json`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Query = strings.Join(args, " ")
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().IntVar(&opts.Top, "top", 10, "number of matches to surface")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	if strings.TrimSpace(opts.Query) == "" {
		return &ui.UserError{Err: errors.New("query is required")}
	}
	// Validate the format up front (guard, not a render dispatch — the
	// rendering lives in pkg/stave — so this does not trip the
	// inline-format-switch lint).
	if opts.Format != "text" && opts.Format != "json" && opts.Format != "" {
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
	}

	out, err := stave.RenderCatalogSearch(ctx, opts.Query, opts.Top, opts.ControlsDir, opts.ChainsDir, opts.Format)
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"render ..."); preserve exit 4.
	}
	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write search results: %w", werr)
	}
	return nil
}
