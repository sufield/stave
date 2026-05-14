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
func writeText(w io.Writer, r readiness.Report) error {
	if _, err := fmt.Fprintln(w, "Stave Readiness Assessment"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "=========================="); err != nil {
		return err
	}

	// Snapshot summary.
	if _, err := fmt.Fprintf(w, "\nObservations:        %d assets across %d asset types\n",
		r.ObservationCount, len(r.ObservedTypes)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Catalog asset types: %d declared by controls\n",
		len(r.CatalogTypes)); err != nil {
		return err
	}

	if len(r.ObservedTypes) > 0 {
		if _, err := fmt.Fprintln(w, "\nObserved asset types:"); err != nil {
			return err
		}
		for _, t := range sortedKeys(r.ObservedTypes) {
			if _, err := fmt.Fprintf(w, "  %-40s %d\n", t, r.ObservedTypes[t]); err != nil {
				return err
			}
		}
	}

	// Control forecast.
	if _, err := fmt.Fprintln(w, "\nControl evaluation forecast:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Total controls:    %d\n", r.Controls.Total); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Can fire:          %d\n", r.Controls.CanFire); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Blocked:           %d (declares an asset type the snapshot does not include)\n",
		r.Controls.Blocked); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Indeterminate:     %d (control declares no applicable_asset_types)\n",
		r.Controls.Indeterminate); err != nil {
		return err
	}

	// Chain forecast.
	if _, err := fmt.Fprintln(w, "\nChain effectiveness:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Total chains:      %d\n", r.Chains.Total); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Can fire:          %d\n", r.Chains.CanFire); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Blocked:           %d (one or more members require an absent asset type)\n",
		r.Chains.Blocked); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Indeterminate:     %d (one or more members declare no applicable_asset_types)\n",
		r.Chains.Indeterminate); err != nil {
		return err
	}

	// Score.
	if _, err := fmt.Fprintf(w, "\nReadiness score:     %.0f%% (of classifiable controls)\n",
		r.ReadinessScore*100); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "                     (input completeness, NOT security posture)"); err != nil {
		return err
	}

	// Action plan.
	if len(r.Actions) > 0 {
		if _, err := fmt.Fprintln(w, "\nAction plan (ranked by unblock count):"); err != nil {
			return err
		}
		for i, a := range r.Actions {
			if _, err := fmt.Fprintf(w, "\n  #%d  %s\n", i+1, a.AssetType); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "      Unblocks: %d chain(s), %d control(s)\n",
				a.ChainsUnblocked, a.ControlsUnblocked); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "      %s\n", a.Description); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "\nNotes:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  - Intent declaration coverage (tags, role-type labels, vendor"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    registry) is not part of this report; deferred pending catalog"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    metadata. See docs/readiness.md for the design."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  - 'Indeterminate' controls/chains lack applicable_asset_types"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    declarations and cannot be statically classified."); err != nil {
		return err
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
