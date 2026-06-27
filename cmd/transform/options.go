package transform

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// options holds flags for `stave transform`.
type options struct {
	inDir    string
	outDir   string
	account  string
	now      string
	format   string
	coverage bool
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.inDir, "in", "i", "raw", "directory of raw AWS CLI JSON files")
	f.StringVarP(&o.outDir, "out", "o", "observations",
		"output directory for the observation file (or - for stdout)")
	f.StringVar(&o.account, "account", "", "AWS account ID for filters whose raw input carries no ARN")
	f.StringVar(&o.now, "now", "", "captured_at timestamp (RFC3339); defaults to the current time")
	f.StringVarP(&o.format, "format", "f", "text", "summary format: text, json")
	f.BoolVar(&o.coverage, "coverage", false, "list the raw input shapes transform recognizes, then exit")
}

// Prepare validates flags at the CLI boundary (PreRunE).
func (o *options) Prepare(_ *cobra.Command) error {
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	if o.now != "" {
		if _, err := time.Parse(time.RFC3339, o.now); err != nil {
			return &ui.UserError{Err: fmt.Errorf("invalid --now %q: want RFC3339 (e.g. 2026-06-27T12:00:00Z): %w", o.now, err)}
		}
	}
	return nil
}

// capturedAt resolves the observation timestamp: --now when set, else now (UTC).
func (o *options) capturedAt() string {
	if o.now != "" {
		return o.now
	}
	return time.Now().UTC().Format(time.RFC3339)
}
