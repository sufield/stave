package exempt

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/pkg/stave"
)

type exportOptions struct {
	File       string
	Format     string
	OutputFile string // --output: path to assessment.json
	SystemUUID string
	Assessor   string
	OutPath    string // --out: write POAM to file instead of stdout
}

// Normalize validates that --format is supported, before any side-effect
// (file loads) runs.
func (o *exportOptions) Normalize() error {
	if o.Format != "oscal-poam" {
		return fmt.Errorf("unsupported format %q (use oscal-poam)", o.Format)
	}
	return nil
}

func newExportCmd() *cobra.Command {
	opts := exportOptions{File: defaultFile, Format: "oscal-poam", Assessor: "Stave automated assessment"}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export risk register as OSCAL POA&M",
		Long: `Export acknowledgments and open findings as an OSCAL Plan of Action
and Milestones (POA&M) document for FedRAMP, HIPAA, and SOC2 submissions.

Exit Codes:
  0   Export complete
  2   Invalid input
  4   Internal error`,
		Example: `  stave exempt export --format oscal-poam --system-uuid <uuid> --out poam.json
  stave exempt export --format oscal-poam --output assessment.json --out poam.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ExportRiskRegister(opts.File, opts.OutputFile, opts.SystemUUID, opts.Assessor, time.Now().UTC())
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			if writeErr := cmdutil.WriteTo(cmd.OutOrStdout(), opts.OutPath, func(w io.Writer) error {
				_, e := w.Write(out)
				return e
			}); writeErr != nil {
				return fmt.Errorf("write POAM: %w", writeErr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acknowledgment YAML file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: oscal-poam")
	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json for open findings")
	cmd.Flags().StringVar(&opts.SystemUUID, "system-uuid", "", "UUID of the System Security Plan")
	cmd.Flags().StringVar(&opts.Assessor, "assessor", opts.Assessor, "assessor name")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "write to file instead of stdout")

	return cmd
}
