// Package sla implements the 'stave sla' command group for SLA policy
// management — init, validate, and simulate.
package sla

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the top-level sla command with subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sla",
		Short: "Manage SLA policy files for remediation deadlines",
		Long: `Manage SLA policy files that define remediation deadlines per severity.

SLA policies are consumed by:
  stave budget  — monitor burn rate against deadlines
  stave rank    — urgency multiplier for prioritization
  stave score   — 25% of posture score (SLA compliance dimension)

Subcommands:
  init       Generate a starter SLA policy file
  validate   Validate an SLA policy file
  simulate   Show posture score impact of an SLA policy`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newValidateCmd())
	cmd.AddCommand(newSimulateCmd())

	return cmd
}
