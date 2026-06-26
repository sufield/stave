// Package pack implements `stave pack` — list and inspect concern packs (named
// cross-cutting control groupings plus a data-requirements manifest).
package pack

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the `stave pack` command tree.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Concern packs — named control groupings and their data requirements",
		Long: `Inspect concern packs: named, cross-cutting groupings of controls (e.g.
"entropy", "quick") plus a requirements manifest describing the exact AWS API
calls and observation signals the pack needs.

A pack is distinct from a compliance --profile (which evaluates a snapshot
against a framework) and from a filesystem domain (-i path): membership is
resolved by control ID, ID-glob pattern, and minimum severity.

Subcommands:
  list           list available packs and their control counts
  show <name>    show a pack's requirements manifest (the data you must collect)

Exit codes: 0 = success, 2 = input error (unknown pack/format), 4 = internal.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newListCmd(), newShowCmd())
	return cmd
}

func newListCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List available concern packs and their control counts",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return runList(cmd, opts) },
	}
	addCommonFlags(cmd, opts)
	return cmd
}

func newShowCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a pack's requirements manifest (AWS calls, signals, collector permissions)",
		Long: `Show a concern pack's requirements manifest: the resolved control count, the
exact AWS API calls to collect, the observation signals the controls read, and
the minimum collector IAM permissions. Copy the calls, run them, and feed the
output to a scoped evaluation.

Example:
  stave pack show entropy`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, args []string) error { return runShow(cmd, opts, args[0]) },
	}
	addCommonFlags(cmd, opts)
	return cmd
}
