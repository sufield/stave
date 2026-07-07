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
	evalTime string
	format   string
	coverage bool
	lint     bool
	scaffold string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.inDir, "in", "i", "raw", "directory of raw AWS CLI JSON files")
	f.StringVarP(&o.outDir, "out", "o", "observations",
		"output directory for the observation file (or - for stdout)")
	f.StringVar(&o.account, "account", "", "AWS account ID for filters whose raw input carries no ARN")
	f.StringVar(&o.evalTime, "eval-time", "", "captured_at timestamp (RFC3339); defaults to the current time")
	f.StringVarP(&o.format, "format", "f", "text", "summary format: text, json")
	f.BoolVar(&o.coverage, "coverage", false, "list the raw input shapes transform recognizes, then exit")
	f.BoolVar(&o.lint, "lint", false, "lint the embedded jq filters (compile + shape checks), then exit")
	f.StringVar(&o.scaffold, "scaffold", "", "scaffold a starter filter for NAME (e.g. kms-keys), then exit")
}

// Prepare validates flags at the CLI boundary (PreRunE).
func (o *options) Prepare(_ *cobra.Command) error {
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	if o.evalTime != "" {
		if _, err := time.Parse(time.RFC3339, o.evalTime); err != nil {
			return &ui.UserError{Err: fmt.Errorf("invalid --eval-time %q: want RFC3339 (e.g. 2026-06-27T12:00:00Z): %w", o.evalTime, err)}
		}
	}
	return nil
}

// capturedAt resolves the observation timestamp: --eval-time when set, else now (UTC).
func (o *options) capturedAt() string {
	if o.evalTime != "" {
		return o.evalTime
	}
	return time.Now().UTC().Format(time.RFC3339)
}
