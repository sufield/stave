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
		Use:   "list",
		Short: "List available concern packs and their control counts",
		Long: `List the available concern packs and how many controls each resolves to from
the active catalog.

A concern pack is a named, cross-cutting grouping of controls (e.g. "entropy",
"quick"). Use a pack name with "stave pack show <name>" to see its data
requirements, or with "stave apply --pack <name>" to scope an evaluation.

Inputs:  --format, -f (text|json); --controls, -i (catalog to resolve against).
Outputs: pack names, titles, and resolved control counts on stdout.

Exit codes: 0 = success, 2 = input error (bad --format), 4 = internal.`,
		Example: `  # List all concern packs
  stave pack list

  # Machine-readable output
  stave pack list --format json`,
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

Inputs:  <name> (pack to show); --format, -f (text|json); --controls, -i.
Outputs: the resolved manifest on stdout.

Exit codes: 0 = success, 2 = input error (unknown pack/format), 4 = internal.`,
		Example: `  # Show the entropy pack's data requirements
  stave pack show entropy

  # Machine-readable output
  stave pack show entropy --format json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, args []string) error { return runShow(cmd, opts, args[0]) },
	}
	addCommonFlags(cmd, opts)
	return cmd
}
