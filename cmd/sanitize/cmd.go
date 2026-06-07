// Package sanitize implements the 'stave sanitize' command for
// standalone snapshot sanitization.
package sanitize

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	Snapshot string
	Rules    string
	OutPath  string
}

// NewCmd constructs the sanitize command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "sanitize",
		Short: "Sanitize a snapshot for cross-boundary sharing",
		Long: `Replace ARNs, account IDs, and sensitive fields with deterministic
tokens for safe cross-boundary sharing. The sanitized snapshot remains
evaluable by stave apply.

Default sanitization hashes asset IDs and replaces 12-digit account
IDs in property values. Custom rules can be provided via --rules.

Inputs:
  --snapshot PATH   Observation snapshot JSON file (required)
  --rules PATH      Custom sanitization rules YAML (optional)
  --out PATH        Output file path (required)

Exit Codes:
  0   Sanitized snapshot written
  2   Invalid input`,
		Example: `  stave sanitize --snapshot snapshot.json --out sanitized.json
  stave sanitize --snapshot snapshot.json --rules rules.yaml --out sanitized.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to observation snapshot JSON (required)")
	cmd.Flags().StringVar(&opts.Rules, "rules", "", "path to custom sanitization rules YAML")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "output file path (required)")
	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "out")

	return cmd
}

func run(opts *options) error {
	// Load + sanitize + marshal live in stave.SanitizeSnapshot so this
	// command depends only on pkg/stave. Input errors (load/read/parse)
	// surface as exit 2 via ui.UserError, preserving the prior messages.
	data, stats, err := stave.SanitizeSnapshot(opts.Snapshot, opts.Rules)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	// Surface the stats so a no-op run (misspelled rule field, empty
	// input) is visible rather than passing silently.
	slog.Debug("sanitize: completed",
		"assets_touched", stats.AssetsTouched,
		"rules_applied", stats.RulesApplied,
		"account_id_hashes", stats.AccountIDHashes)
	if stats.AssetsTouched == 0 {
		slog.Warn("sanitize: no assets matched — input may be empty or rules may be mis-targeted")
	}

	if err := fsutil.SafeWriteFile(opts.OutPath, data, fsutil.ConfigWriteOpts()); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Wrote sanitized snapshot to %s\n", opts.OutPath)
	return nil
}
