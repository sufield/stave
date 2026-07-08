//go:build ignore

package main

import (
	"fmt"
	"os"
	"strings"
)

func reportText(all []discoveredPath, novel, confirmed []discoveredPath, counts map[string]int, opts *options) {
	w := os.Stdout

	fmt.Fprintln(w, "═══════════════════════════════════════════════")
	fmt.Fprintln(w, "CHAIN DISCOVERY")
	fmt.Fprintln(w, "═══════════════════════════════════════════════")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "DATALOG EVALUATION:")
	relations := []string{"privesc_path", "access_path", "escalation_path", "exfil_path", "external_reach", "confused_deputy_path", "path_condition"}
	for _, r := range relations {
		fmt.Fprintf(w, "  %-26s %d\n", r+":", counts[r])
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "CLASSIFICATION:  %d total paths\n", len(all))
	catCounts := map[string]int{}
	for _, p := range all {
		catCounts[p.Category]++
	}
	for _, cat := range []string{"escalation", "exfiltration", "external-reach", "confused-deputy"} {
		if n := catCounts[cat]; n > 0 {
			fmt.Fprintf(w, "  %-26s %d\n", cat+":", n)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "DEDUPLICATION:  %d novel, %d confirmed\n", len(novel), len(confirmed))
	fmt.Fprintln(w)

	if len(novel) > 0 {
		fmt.Fprintln(w, "═══════════════════════════════════════════════")
		fmt.Fprintln(w, "NOVEL CHAINS (not covered by existing YAMLs):")
		fmt.Fprintln(w, "═══════════════════════════════════════════════")
		for i, p := range novel {
			fmt.Fprintf(w, "\nCHAIN %d: %s (%d hops)\n", i+1, p.Category, p.Hops)
			fmt.Fprintf(w, "  Source:   %s\n", shorten(p.Source))
			fmt.Fprintf(w, "  Target:   %s\n", shorten(p.Target))
			if p.Action != "" {
				fmt.Fprintf(w, "  Action:   %s\n", p.Action)
			}
			if p.ViaRole != "" {
				fmt.Fprintf(w, "  Via:      %s\n", shorten(p.ViaRole))
			}
			if p.Service != "" {
				fmt.Fprintf(w, "  Service:  %s\n", p.Service)
			}
			fmt.Fprintf(w, "  Path:     %s\n", formatPath(p.Path))
		}
		fmt.Fprintln(w)
	}

	if len(confirmed) > 0 {
		fmt.Fprintln(w, "═══════════════════════════════════════════════")
		fmt.Fprintf(w, "CONFIRMED CHAINS: %d paths match existing chain patterns\n", len(confirmed))
		fmt.Fprintln(w, "═══════════════════════════════════════════════")
		catConfirmed := map[string]int{}
		for _, p := range confirmed {
			catConfirmed[p.Category]++
		}
		for cat, n := range catConfirmed {
			fmt.Fprintf(w, "  %-26s %d\n", cat+":", n)
		}
		fmt.Fprintln(w)
	}

	if len(novel) == 0 && len(confirmed) == 0 {
		fmt.Fprintln(w, "No security-relevant paths discovered.")
	}
}

func shorten(arn string) string {
	if len(arn) <= 80 {
		return arn
	}
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return "…/" + parts[len(parts)-1]
	}
	return arn[:40] + "…" + arn[len(arn)-37:]
}

func formatPath(path []string) string {
	shortened := make([]string, len(path))
	for i, p := range path {
		shortened[i] = shorten(p)
	}
	return strings.Join(shortened, " → ")
}
