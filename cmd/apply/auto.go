package apply

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// printAutoPlan resolves services to controls, builds a severity-weighted
// plan preview, and prints it to w (typically stderr) before the standard
// evaluation runs. This is the "discover→plan" part of --auto.
func printAutoPlan(w io.Writer, opts *Options) error {
	result, err := stave.AutoPlanSummary(opts.Packs, opts.Services, opts.ControlsDir, !opts.controlsSet)
	if err != nil {
		return fmt.Errorf("auto plan: %w", err)
	}
	if result == nil {
		return nil
	}

	order := make([]stave.ServiceSeverityCounts, len(result.Counts))
	copy(order, result.Counts)
	slices.SortStableFunc(order, func(a, b stave.ServiceSeverityCounts) int {
		if c := cmp.Compare(b.Critical, a.Critical); c != 0 {
			return c
		}
		return cmp.Compare(b.High, a.High)
	})

	var total stave.ServiceSeverityCounts
	for _, c := range result.Counts {
		total.Critical += c.Critical
		total.High += c.High
		total.Medium += c.Medium
		total.Low += c.Low
		total.Info += c.Info
		total.Total += c.Total
	}

	fmt.Fprintf(w, "Plan for services: %s\n\n", strings.Join(result.Services, ", "))
	fmt.Fprintf(w, "%-14s %9s %9s %5s %7s %5s\n", "Service", "Controls", "Critical", "High", "Medium", "Low")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 56))
	for _, r := range result.Counts {
		fmt.Fprintf(w, "%-14s %9d %9d %5d %7d %5d\n",
			r.Service, r.Total, r.Critical, r.High, r.Medium, r.Low)
	}
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 56))
	fmt.Fprintf(w, "%-14s %9d %9d %5d %7d %5d\n\n",
		"total", total.Total, total.Critical, total.High, total.Medium, total.Low)

	fmt.Fprintf(w, "Evaluation order (most critical first):\n")
	for i, r := range order {
		fmt.Fprintf(w, "  %d. %s\n", i+1, r.Service)
	}
	fmt.Fprintln(w)

	return nil
}
