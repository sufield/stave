// Package verify implements the 'stave verify --archive' command for
// evidence archive continuity verification.
package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	av "github.com/sufield/stave/internal/app/archiveverify"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	ArchivePath string
	Period      string
	MaxGap      string
	Format      string
	OutFile     string
	Strict      bool
}

// NewCmd constructs the verify command.
func NewCmd() *cobra.Command {
	opts := &options{
		MaxGap: "25h",
		Format: "table",
	}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify evidence archive integrity and continuity",
		Long: `Verify that an evidence archive produced by stave collect is
complete and uninterrupted across a time period.

Checks:
  - Manifest SHA-256 integrity
  - Per-run file checksum verification
  - Temporal continuity (no gaps exceeding max-gap)
  - Period start and end coverage

Inputs:
  --archive PATH       Path to evidence archive directory (required)
  --period STRING      Time period: 2026-Q1 | 2026-01 |
                       2026-01-01:2026-03-31 (required)
  --max-gap DURATION   Max acceptable gap (default: 25h)
  --strict             Fail on any gap regardless of size
  --format STRING      table (default) | json | markdown
  --out PATH           Write attestation to file

Exit Codes:
  0   PASS — all bundles valid, no gaps exceeding max-gap
  1   FAIL — invalid bundles or gaps exceeding max-gap
  2   Invalid input
  3   No bundles found in period`,
		Example: `  # Verify Q1 2026
  stave verify --archive ./evidence/ --period 2026-Q1

  # Strict mode
  stave verify --archive ./evidence/ --period 2026-Q1 --strict

  # JSON attestation document
  stave verify --archive ./evidence/ --period 2026-Q1 \
    --format json --out attestation.json

  # Markdown for audit package
  stave verify --archive ./evidence/ --period 2026-Q1 \
    --format markdown --out attestation.md`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.ArchivePath, "archive", "", "path to evidence archive directory (required)")
	cmd.Flags().StringVar(&opts.Period, "period", "", "time period to verify (required)")
	cmd.Flags().StringVar(&opts.MaxGap, "max-gap", "25h", "maximum acceptable gap between collections")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | markdown")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write attestation to file")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "fail on any gap regardless of size")

	_ = cmd.MarkFlagRequired("archive")
	_ = cmd.MarkFlagRequired("period")

	return cmd
}

func runVerify(stdout io.Writer, opts *options) error {
	start, end, label, err := av.ParsePeriod(opts.Period)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse period: %w", err)}
	}

	maxGap, parseErr := time.ParseDuration(opts.MaxGap)
	if parseErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse max-gap: %w", parseErr)}
	}

	attestation, verifyErr := av.Verify(av.VerifyInput{
		ArchivePath: opts.ArchivePath,
		PeriodStart: start,
		PeriodEnd:   end,
		PeriodLabel: label,
		MaxGapHours: maxGap.Hours(),
		Strict:      opts.Strict,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if verifyErr != nil {
		return fmt.Errorf("verify archive: %w", verifyErr)
	}

	if writeErr := cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		switch opts.Format {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(attestation); encErr != nil {
				return fmt.Errorf("encode json: %w", encErr)
			}
			return nil
		case "markdown":
			if mdErr := av.WriteMarkdown(w, attestation); mdErr != nil {
				return fmt.Errorf("render markdown: %w", mdErr)
			}
			return nil
		default:
			if tblErr := av.WriteTable(w, attestation); tblErr != nil {
				return fmt.Errorf("render table: %w", tblErr)
			}
			return nil
		}
	}); writeErr != nil {
		return writeErr
	}

	if attestation.Failed() {
		return ui.ErrViolationsFound
	}
	return nil
}
