package snapshot

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// queryOptions holds the raw input from the `stave snapshot query`
// flags plus the values resolved from them in PreRunE. Business
// logic reads the resolved fields; cobra never reaches past
// Normalize().
type queryOptions struct {
	// Raw flag values.
	Dir       string
	OlderThan string
	NewerThan string
	Health    bool
	Format    string
	NowRaw    string

	// Resolved in Normalize.
	Now          time.Time
	OlderThanDur time.Duration
	NewerThanDur time.Duration
	HasOlderThan bool
	HasNewerThan bool
}

// defaultQueryOptions returns the zero-state Options with flag
// defaults populated. Flag binding reads these so --help shows the
// defaults consistently.
func defaultQueryOptions() queryOptions {
	return queryOptions{
		Dir:    "observations",
		Format: "text",
	}
}

// BindFlags attaches the options to a cobra command.
func (o *queryOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.Dir, "dir", o.Dir, "Observation snapshots directory")
	f.StringVar(&o.OlderThan, "older-than", "", "Filter to snapshots older than duration (e.g. 720h)")
	f.StringVar(&o.NewerThan, "newer-than", "", "Filter to snapshots newer than duration (e.g. 48h)")
	f.BoolVar(&o.Health, "health", false, "Produce archive health summary")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	f.StringVar(&o.NowRaw, "now", "", "Override current time (RFC3339) for deterministic output")
}

// Normalize resolves defaults, parses durations and --now, and
// validates flag combinations. Called from PreRunE — once this
// returns, downstream code reads only the resolved fields and
// never touches *cobra.Command.
func (o *queryOptions) Normalize() error {
	if o.Dir == "" {
		o.Dir = "observations"
	}

	o.Now = time.Now().UTC()
	if o.NowRaw != "" {
		t, err := time.Parse(time.RFC3339, o.NowRaw)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("parse --now: %w", err)}
		}
		o.Now = t
	}

	if o.OlderThan != "" {
		d, err := time.ParseDuration(o.OlderThan)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("parse --older-than: %w", err)}
		}
		o.OlderThanDur = d
		o.HasOlderThan = true
	}
	if o.NewerThan != "" {
		d, err := time.ParseDuration(o.NewerThan)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("parse --newer-than: %w", err)}
		}
		o.NewerThanDur = d
		o.HasNewerThan = true
	}
	return nil
}
