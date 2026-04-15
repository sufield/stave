package compliance

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

type options struct {
	Snapshot       string
	Profile        string
	Format         string
	Out            string
	MinSeverity    string
	IncludePass    bool
	Verbose        bool
	Composite      bool
	SystemUUID     string
	Assessor       string
	AssessmentUUID string
	ProfileFiles   []string
}

// NewCmd creates the compliance evidence export subcommand.
func NewCmd(newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory) *cobra.Command {
	opts := &options{
		Format:      "json",
		MinSeverity: "all",
	}

	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Export compliance evidence package",
		Long: `Evaluate a snapshot against a compliance framework profile and
export a structured evidence package as JSON.

Runs the full assessment pipeline with evidence generation, evaluates
the requested compliance profile, and produces a requirement-centric
evidence package with per-requirement scores, gaps, and reasoning traces.

Supported profiles:
  hipaa              HIPAA Security Rule
  soc2               SOC 2 Trust Service Criteria
  pci_dss_v4.0       PCI-DSS v4.0
  fedramp_moderate   FedRAMP Moderate (NIST 800-53 Rev 5)
  cis_aws_v3.0       CIS AWS Foundations Benchmark v3.0

Exit Codes:
  0   All required requirements satisfied
  1   One or more required requirements failed
  2   Invalid input (bad profile ID, missing snapshot)
  4   Internal error

Examples:
  stave export compliance --snapshot obs.json --profile hipaa

  stave export compliance --snapshot obs.json --profile soc2 \
    --include-pass --out evidence.json

  stave export compliance --snapshot obs.json --profile pci_dss_v4.0 \
    --min-severity high`,
		Example: `  stave export compliance --snapshot obs.json --profile hipaa
  stave export compliance --snapshot obs.json --profile soc2 --out evidence.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCompliance(cmd.Context(), opts, cmd.OutOrStdout(), newCtlRepo, newCELEvaluator)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.Profile, "profile", "", "compliance profile ID (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "output format: json | table | markdown")
	cmd.Flags().StringVar(&opts.Out, "out", "", "write output to file instead of stdout")
	cmd.Flags().StringVar(&opts.MinSeverity, "min-severity", "all", "minimum severity filter: critical|high|medium|low|all")
	cmd.Flags().BoolVar(&opts.IncludePass, "include-pass", false, "include passing evidence records")
	cmd.Flags().BoolVar(&opts.Verbose, "verbose", false, "include reasoning traces in table output")

	cmd.Flags().BoolVar(&opts.Composite, "composite", false, "force composite report even for single framework")
	cmd.Flags().StringVar(&opts.SystemUUID, "system-uuid", "", "UUID of the System Security Plan (for eMASS/OSCAL)")
	cmd.Flags().StringVar(&opts.Assessor, "assessor", "Stave automated assessment", "assessor name (for OSCAL)")
	cmd.Flags().StringVar(&opts.AssessmentUUID, "assessment-uuid", "", "UUID for this assessment result (for OSCAL)")
	cmd.Flags().StringSliceVar(&opts.ProfileFiles, "profile-file", nil, "path to custom profile YAML (can be repeated)")

	_ = cmd.MarkFlagRequired("snapshot")
	// --profile is not required when --profile-file is specified.

	return cmd
}
