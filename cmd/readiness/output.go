package readiness

import (
	"fmt"
	"io"
	"slices"

	"github.com/sufield/stave/internal/app/readiness"
	"github.com/sufield/stave/internal/core/kernel"
)

// writeText renders the human-readable readiness report. The
// shape is grep-friendly (plain prose, no ANSI), the rule the
// rest of Stave's text formatters already follow.
//
// Sections are factored into per-concern helpers so this top-level
// stays a thin orchestrator; cyclomatic complexity would otherwise
// climb past the gocyclo threshold once every Fprintln contributes
// its own error branch.
func writeText(w io.Writer, r readiness.Report) error {
	sections := []func(io.Writer, readiness.Report) error{
		writeHeader,
		writeSnapshotSummary,
		writeObservedTypes,
		writeControlForecast,
		writeChainForecast,
		writeScore,
		writeActionPlan,
		writeNotes,
	}
	for _, fn := range sections {
		if err := fn(w, r); err != nil {
			return err
		}
	}
	return nil
}

func writeHeader(w io.Writer, _ readiness.Report) error {
	if _, err := fmt.Fprintln(w, "Stave Readiness Assessment"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "==========================")
	return err
}

func writeSnapshotSummary(w io.Writer, r readiness.Report) error {
	if _, err := fmt.Fprintf(w, "\nObservations:        %d assets across %d asset types\n",
		r.ObservationCount, len(r.ObservedTypes)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Catalog asset types: %d declared by controls\n",
		len(r.CatalogTypes))
	return err
}

func writeObservedTypes(w io.Writer, r readiness.Report) error {
	if len(r.ObservedTypes) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nObserved asset types:"); err != nil {
		return err
	}
	for _, t := range sortedKeys(r.ObservedTypes) {
		if _, err := fmt.Fprintf(w, "  %-40s %d\n", t, r.ObservedTypes[t]); err != nil {
			return err
		}
	}
	return nil
}

func writeControlForecast(w io.Writer, r readiness.Report) error {
	lines := []string{
		"\nControl evaluation forecast:",
		fmt.Sprintf("  Total controls:    %d", r.Controls.Total),
		fmt.Sprintf("  Can fire:          %d", r.Controls.CanFire),
		fmt.Sprintf("  Blocked:           %d (declares an asset type the snapshot does not include)", r.Controls.Blocked),
		fmt.Sprintf("  Indeterminate:     %d (control declares no applicable_asset_types)", r.Controls.Indeterminate),
	}
	return writeLines(w, lines)
}

func writeChainForecast(w io.Writer, r readiness.Report) error {
	lines := []string{
		"\nChain effectiveness:",
		fmt.Sprintf("  Total chains:      %d", r.Chains.Total),
		fmt.Sprintf("  Can fire:          %d", r.Chains.CanFire),
		fmt.Sprintf("  Blocked:           %d (one or more members require an absent asset type)", r.Chains.Blocked),
		fmt.Sprintf("  Indeterminate:     %d (one or more members declare no applicable_asset_types)", r.Chains.Indeterminate),
	}
	return writeLines(w, lines)
}

func writeScore(w io.Writer, r readiness.Report) error {
	if _, err := fmt.Fprintf(w, "\nReadiness score:     %.0f%% (of classifiable controls)\n",
		r.ReadinessScore*100); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "                     (input completeness, NOT security posture)")
	return err
}

func writeActionPlan(w io.Writer, r readiness.Report) error {
	if len(r.Actions) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nAction plan (ranked by unblock count):"); err != nil {
		return err
	}
	for i, a := range r.Actions {
		lines := []string{
			fmt.Sprintf("\n  #%d  %s", i+1, a.AssetType),
			fmt.Sprintf("      Unblocks: %d chain(s), %d control(s)", a.ChainsUnblocked, a.ControlsUnblocked),
			"      " + a.Description,
		}
		if err := writeLines(w, lines); err != nil {
			return err
		}
	}
	return nil
}

func writeNotes(w io.Writer, _ readiness.Report) error {
	return writeLines(w, []string{
		"\nNotes:",
		"  - Intent declaration coverage (tags, role-type labels, vendor",
		"    registry) is not part of this report; deferred pending catalog",
		"    metadata. See docs/readiness.md for the design.",
		"  - 'Indeterminate' controls/chains lack applicable_asset_types",
		"    declarations and cannot be statically classified.",
	})
}

// writeLines emits each line followed by a newline, returning the
// first error encountered. The sections above use this as the
// shared error-propagation pattern so per-section helpers stay
// branch-free over each Fprintln call site.
func writeLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys(m map[kernel.AssetType]int) []kernel.AssetType {
	keys := make([]kernel.AssetType, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
