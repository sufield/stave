package cliflags

import (
	"fmt"

	"github.com/spf13/cobra"
)

// MustMarkRequired marks a flag as required and panics on error.
//
// Cobra's MarkFlagRequired only errors when the named flag is not
// registered on the command — a programming-time invariant under
// the developer's control, not a runtime condition. The previous
// pattern across cmd/* was `_ = cmd.MarkFlagRequired("foo")` which
// silently dropped that mistake; if a flag was renamed or removed,
// the "required" annotation no longer attached to anything and
// the command would happily run without it.
//
// MustMarkRequired panics with the offending flag name so the
// developer sees the typo at startup. Use it for every required
// flag in cmd/* — the pattern is uniform across commands and one
// missed mark turns into a runtime UX regression rather than a
// build failure.
func MustMarkRequired(cmd *cobra.Command, flag string) {
	if err := cmd.MarkFlagRequired(flag); err != nil {
		panic(fmt.Sprintf("cliflags.MustMarkRequired: flag %q: %v", flag, err))
	}
}
