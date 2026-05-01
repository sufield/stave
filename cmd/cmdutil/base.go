package cmdutil

import "github.com/spf13/cobra"

// NewBase returns a *cobra.Command with the project-wide defaults applied:
// SilenceUsage=true and SilenceErrors=true so spf13/cobra does not print
// usage or wrap returned errors. Callers populate Long, Example, Args,
// RunE, and flags as usual.
//
// Existing commands continue to work with the inline struct-literal form;
// new commands should prefer this helper to avoid forgetting either flag.
func NewBase(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:           use,
		Short:         short,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
