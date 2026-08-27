package fieldcov

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// WriteTable writes the coverage report in human-readable table format.
func WriteTable(w io.Writer, r *Report) {
	fmt.Fprintln(w, "STAVE COVERAGE ANALYSIS")
	fmt.Fprintf(w, "Snapshot:  %s\n", r.Snapshot)
	fmt.Fprintf(w, "Controls:  %d total\n\n", r.Summary.Total)

	fmt.Fprintln(w, "SUMMARY")
	fmt.Fprintf(w, "  Evaluable:       %d controls  (%.1f%%)\n",
		r.Summary.Evaluable, pct(r.Summary.Evaluable, r.Summary.Total))
	fmt.Fprintf(w, "  Incomplete:      %d controls  (%.1f%%)\n",
		r.Summary.Incomplete, pct(r.Summary.Incomplete, r.Summary.Total))
	fmt.Fprintf(w, "  Silent risk:     %d controls  (%.1f%%)\n",
		r.Summary.SilentRisk, pct(r.Summary.SilentRisk, r.Summary.Total))
	fmt.Fprintf(w, "  No assets:       %d controls  (%.1f%%)\n",
		r.Summary.NoAssets, pct(r.Summary.NoAssets, r.Summary.Total))
	fmt.Fprintf(w, "  Not applicable:  %d controls  (%.1f%%)\n",
		r.Summary.NotApplicable, pct(r.Summary.NotApplicable, r.Summary.Total))
	fmt.Fprintln(w)

	if len(r.SilentRisk) > 0 {
		fmt.Fprintln(w, "SILENT RISK — controls that may produce false PASS verdicts")
		fmt.Fprintln(w, strings.Repeat("-", 72))
		fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n", "Control", "Missing Field", "Severity", "Frameworks")
		fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n",
			strings.Repeat("-", 28), strings.Repeat("-", 28), strings.Repeat("-", 8), strings.Repeat("-", 10))
		for i := range r.SilentRisk {
			cr := &r.SilentRisk[i]
			for _, f := range cr.MissingFields {
				fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n",
					cr.ControlID, f, strings.ToUpper(cr.Severity.String()), strings.Join(shortFrameworks(cr.Frameworks), " "))
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.IncompleteResults) > 0 {
		fmt.Fprintln(w, "INCOMPLETE — controls that will fire INCOMPLETE verdicts")
		fmt.Fprintln(w, strings.Repeat("-", 72))
		fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n", "Control", "Missing Field", "Severity", "Frameworks")
		fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n",
			strings.Repeat("-", 28), strings.Repeat("-", 28), strings.Repeat("-", 8), strings.Repeat("-", 10))
		for i := range r.IncompleteResults {
			cr := &r.IncompleteResults[i]
			for _, f := range cr.MissingFields {
				fmt.Fprintf(w, "  %-30s %-30s %-8s %s\n",
					cr.ControlID, f, strings.ToUpper(cr.Severity.String()), strings.Join(shortFrameworks(cr.Frameworks), " "))
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.ShoppingList) > 0 {
		fmt.Fprintln(w, "EXTRACTOR SHOPPING LIST — fields to add to close gaps")
		fmt.Fprintln(w, strings.Repeat("-", 72))
		var assetTypes []string
		for at := range r.ShoppingList {
			assetTypes = append(assetTypes, at)
		}
		slices.Sort(assetTypes)
		for _, at := range assetTypes {
			fmt.Fprintf(w, "\n  Asset type: %s\n", at)
			for _, item := range r.ShoppingList[at] {
				fmt.Fprintf(w, "    + %-40s (%s — %s)\n",
					item.Field, strings.Join(controlIDStrings(item.RequiredBy), ", "), strings.ToUpper(item.MaxSeverity.String()))
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.FrameworkCoverage) > 0 {
		fmt.Fprintln(w, "COMPLIANCE FRAMEWORK IMPACT")
		fmt.Fprintln(w, strings.Repeat("-", 72))
		fmt.Fprintf(w, "  %-12s %-12s %-12s %-12s %s\n",
			"Framework", "Evaluable", "Incomplete", "Silent Risk", "Coverage")
		fmt.Fprintf(w, "  %-12s %-12s %-12s %-12s %s\n",
			strings.Repeat("-", 10), strings.Repeat("-", 10),
			strings.Repeat("-", 10), strings.Repeat("-", 10), strings.Repeat("-", 8))
		var fws []string
		for fw := range r.FrameworkCoverage {
			fws = append(fws, fw)
		}
		slices.Sort(fws)
		for _, fw := range fws {
			fc := r.FrameworkCoverage[fw]
			fmt.Fprintf(w, "  %-12s %-12s %-12d %-12d %.1f%%\n",
				shortFramework(fw),
				fmt.Sprintf("%d/%d", fc.Evaluable, fc.Total),
				fc.Incomplete, fc.SilentRisk, fc.CoveragePct)
		}
	}
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func shortFrameworks(fws []string) []string {
	out := make([]string, len(fws))
	for i, fw := range fws {
		out[i] = shortFramework(fw)
	}
	return out
}

func controlIDStrings(ids []kernel.ControlID) []string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = string(id)
	}
	return s
}

func shortFramework(fw string) string {
	switch {
	case strings.Contains(fw, "hipaa"):
		return "HIPAA"
	case strings.Contains(fw, "nist_800"):
		return "NIST"
	case strings.Contains(fw, "cis"):
		return "CIS"
	case strings.Contains(fw, "fedramp"):
		return "FedRAMP"
	case strings.Contains(fw, "pci"):
		return "PCI"
	case strings.Contains(fw, "soc2"):
		return "SOC2"
	case strings.Contains(fw, "gdpr"):
		return "GDPR"
	default:
		return strings.ToUpper(fw)
	}
}
