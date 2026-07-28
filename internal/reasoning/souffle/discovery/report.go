//go:build ignore

package main

import (
	"fmt"
	"os"
	"strings"
)

func reportText(all []discoveredPath, novel, confirmed []discoveredPath, counts map[string]int, opts *options) {
	reportTextVerified(all, novel, confirmed, counts, opts, nil)
}

func reportTextVerified(all []discoveredPath, novel, confirmed []discoveredPath, counts map[string]int, opts *options, verification map[int]verifyStatus) {
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

	if verification != nil {
		engine := "contradiction"
		for _, v := range verification {
			if v.Engine != "" && v.Engine != "none" {
				engine = v.Engine
				break
			}
		}
		fmt.Fprintf(w, "CONDITION VERIFICATION (engine: %s):\n", engine)
		var sat, unsat, uncon int
		for _, v := range verification {
			switch v.Status {
			case "satisfiable":
				sat++
			case "unsatisfiable":
				unsat++
			case "unconstrained":
				uncon++
			}
		}
		fmt.Fprintf(w, "  %-26s %d\n", "satisfiable:", sat)
		fmt.Fprintf(w, "  %-26s %d\n", "unsatisfiable:", unsat)
		fmt.Fprintf(w, "  %-26s %d\n", "unconstrained:", uncon)
		fmt.Fprintln(w)
	}

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
			printVerification(w, i, verification)
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

func printVerification(w *os.File, idx int, verification map[int]verifyStatus) {
	if verification == nil {
		return
	}
	v, ok := verification[idx]
	if !ok {
		return
	}
	fmt.Fprintf(w, "  Verify:   %s", v.Status)
	if v.Conditions > 0 {
		fmt.Fprintf(w, " (%d conditions, %s)", v.Conditions, v.Engine)
	}
	fmt.Fprintln(w)
	for _, c := range v.Conflicts {
		fmt.Fprintf(w, "            conflict: %s\n", c)
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
