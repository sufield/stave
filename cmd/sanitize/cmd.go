// Package sanitize implements the 'stave sanitize' command for
// standalone snapshot sanitization.
package sanitize

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/adapters/observations"
	appsanitize "github.com/sufield/stave/internal/app/sanitize"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func run(opts *options) error {
	snaps, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}

	cfg := appsanitize.DefaultConfig()
	if opts.Rules != "" {
		data, readErr := fsutil.ReadFileLimited(opts.Rules)
		if readErr != nil {
			return &ui.UserError{Err: fmt.Errorf("read rules: %w", readErr)}
		}
		if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
			return &ui.UserError{Err: fmt.Errorf("parse rules: %w", unmarshalErr)}
		}
	}

	appsanitize.Sanitize(snaps, cfg)

	// Re-wrap into bundle format.
	bundle := observations.ObservationBundle{
		SchemaVersion: "obs.v0.1",
		Snapshots:     snaps,
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sanitized output: %w", err)
	}

	if err := os.WriteFile(opts.OutPath, data, 0o644); err != nil { //nolint:gosec // user-specified output file
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Wrote sanitized snapshot to %s\n", opts.OutPath)
	return nil
}
