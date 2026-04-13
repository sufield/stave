// Package telemetry implements the 'stave telemetry' command for emitting
// structured NDJSON telemetry from assessment output.
package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	apptelemetry "github.com/sufield/stave/internal/app/telemetry"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	InputPath   string
	Severity    string
	ResourceARN string
}

// NewCmd constructs the top-level telemetry command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "telemetry",
		Short: "Emit structured NDJSON telemetry from assessment output",
		Long: `Telemetry reads assessment JSON (from stave apply) and emits one NDJSON
line per finding — consumable by Vector, Fluent Bit, Splunk, Logstash,
Loki, or any log shipper.

This is a format converter, not a re-evaluator. It transforms Stave's
deterministic reasoning output into the structured telemetry stream that
dashboards, SIEM pipelines, and compliance trending systems consume.

Inputs:
  stdin or --in       Assessment JSON from stave apply --format json
  --severity          Comma-separated severity filter (default: all)
  --resource          Scope to a specific resource ARN (default: all)

Output:
  NDJSON to stdout — one JSON object per line, newline terminated.
  Append-safe: results can be appended to a file without re-parsing.

Exit Codes:
  0   Telemetry emitted
  2   Input error` + metadata.OfflineHelpSuffix,
		Example: `  # Pipe from apply
  stave apply --format json | stave telemetry

  # From file
  stave telemetry --in assessment.json

  # Filter by severity
  stave telemetry --in assessment.json --severity critical,high

  # Scope to one resource
  stave telemetry --in assessment.json --resource arn:aws:s3:::prod-bucket`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.InputPath, "in", "", "Path to assessment JSON (default: stdin)")
	cmd.Flags().StringVar(&opts.Severity, "severity", "", "Comma-separated severity filter (e.g., critical,high)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "Scope to a specific resource ARN")

	return cmd
}

func run(stdout io.Writer, opts *options) error {
	data, err := readInput(opts.InputPath)
	if err != nil {
		return err
	}

	var assessment report.Assessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		return fmt.Errorf("parse assessment: %w", err)
	}

	filter := buildFilter(opts)
	events := apptelemetry.MapAssessment(&assessment, filter)

	// Stream NDJSON: one JSON object per line.
	enc := json.NewEncoder(stdout)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return fmt.Errorf("encode telemetry event: %w", err)
		}
	}

	return nil
}

func readInput(path string) ([]byte, error) {
	if path != "" {
		return fsutil.ReadFileLimited(path)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("no assessment data provided (pipe from stave apply --format json or use --in)")
	}
	return data, nil
}

func buildFilter(opts *options) apptelemetry.Filter {
	filter := apptelemetry.Filter{
		ResourceARN: opts.ResourceARN,
	}
	if opts.Severity != "" {
		filter.Severities = make(map[string]bool)
		for s := range strings.SplitSeq(opts.Severity, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(s))
			if trimmed != "" {
				filter.Severities[trimmed] = true
			}
		}
	}
	return filter
}
