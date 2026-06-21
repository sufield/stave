package readiness

import (
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/sufield/stave/pkg/stave"
)

// writeText renders the human-readable readiness report. The
// shape is grep-friendly (plain prose, no ANSI), the rule the
// rest of Stave's text formatters already follow.
//
// Sections are factored into per-concern helpers so this top-level
// stays a thin orchestrator; cyclomatic complexity would otherwise
// climb past the gocyclo threshold once every Fprintln contributes
// its own error branch.
func writeText(w io.Writer, r stave.ReadinessReport) error {
	sections := []func(io.Writer, stave.ReadinessReport) error{
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

func writeHeader(w io.Writer, _ stave.ReadinessReport) error {
	if _, err := fmt.Fprintln(w, "Stave Readiness Assessment"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "==========================")
	return err
}

func writeSnapshotSummary(w io.Writer, r stave.ReadinessReport) error {
	if _, err := fmt.Fprintf(w, "\nObservations:        %d assets across %d asset types\n",
		r.ObservationCount, len(r.ObservedTypes)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Catalog asset types: %d declared by controls\n",
		len(r.CatalogTypes))
	return err
}

func writeObservedTypes(w io.Writer, r stave.ReadinessReport) error {
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

func writeControlForecast(w io.Writer, r stave.ReadinessReport) error {
	// Three buckets shown with share-of-total percentages so the
	// operator reads "n controls, X% of the catalog" without
	// confusing the share-of-total with the readiness score
	// (share-of-classifiable, printed below).
	c := r.Controls
	lines := []string{
		"\nControl evaluation forecast:",
		fmt.Sprintf("  Total controls:    %d", c.Total),
		fmt.Sprintf("  Confirmed active:  %d (%.1f%%) — can evaluate your observations", c.CanFire, c.CanFirePct),
		fmt.Sprintf("  Confirmed blocked: %d (%.1f%%) — declares an asset type the snapshot does not include", c.Blocked, c.BlockedPct),
		fmt.Sprintf("  Indeterminate:     %d (%.1f%%) — control declares no applicable_asset_types", c.Indeterminate, c.IndeterminatePct),
	}
	return writeLines(w, lines)
}

func writeChainForecast(w io.Writer, r stave.ReadinessReport) error {
	c := r.Chains
	lines := []string{
		"\nChain effectiveness:",
		fmt.Sprintf("  Total chains:      %d", c.Total),
		fmt.Sprintf("  Confirmed active:  %d (%.1f%%) — every member can fire", c.CanFire, c.CanFirePct),
		fmt.Sprintf("  Confirmed blocked: %d (%.1f%%) — one or more members require an absent asset type", c.Blocked, c.BlockedPct),
		fmt.Sprintf("  Indeterminate:     %d (%.1f%%) — one or more members declare no applicable_asset_types", c.Indeterminate, c.IndeterminatePct),
	}
	return writeLines(w, lines)
}

func writeScore(w io.Writer, r stave.ReadinessReport) error {
	if _, err := fmt.Fprintf(w, "\nReadiness score:     %.1f%% (of classifiable controls)\n",
		r.ReadinessScore*100); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "                     denominator: %s\n", r.ReadinessDenominator); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "                     (input completeness, NOT security posture)")
	return err
}

func writeActionPlan(w io.Writer, r stave.ReadinessReport) error {
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

func writeNotes(w io.Writer, _ stave.ReadinessReport) error {
	return writeLines(w, []string{
		"\nNotes:",
		"  - For field-level gaps (which observation properties are absent",
		"    and what chains they unlock), run: stave gaps --observations <dir>",
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

func sortedKeys(m map[stave.AssetType]int) []stave.AssetType {
	return slices.Sorted(maps.Keys(m))
}
