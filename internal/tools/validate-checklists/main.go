// validate-checklists verifies structural and partition invariants
// on every compliance framework YAML file under data/frameworks/.
//
// Structural (all files): parses; has name/standard; has checks;
// every check has an id; IDs are unique within the file.
//
// Partition (verdict-bearing files — detected by presence of a verdict
// field on any check, not by filename): every check has a verdict;
// verdict is from the allowed vocabulary; EVIDENCE-GATED rows have a
// non-empty condition; OOS rows have a non-empty reason; verdict
// counts sum to the total check count.
//
// Usage: go run ./internal/tools/validate-checklists
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type checklist struct {
	Name     string  `yaml:"name"`
	Standard string  `yaml:"standard"`
	Total    int     `yaml:"total"`
	Checks   []check `yaml:"checks"`
}

func (c *checklist) displayName() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Standard
}

type check struct {
	ID               string `yaml:"id"`
	Service          string `yaml:"service"`
	Description      string `yaml:"description"`
	Verdict          string `yaml:"verdict"`
	VerdictReason    string `yaml:"verdict_reason"`
	VerdictCondition string `yaml:"verdict_condition"`
}

var allowedVerdicts = map[string]bool{
	"COVERED":        true,
	"N-A":            true,
	"EVIDENCE-GATED": true,
	"GAP-AUTHOR":     true,
	"OOS":            true,
}

func validate(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}
	return validateBytes(path, data)
}

func validateBytes(path string, data []byte) []string {
	var cl checklist
	if err := yaml.Unmarshal(data, &cl); err != nil {
		return []string{fmt.Sprintf("%s: parse error: %v", path, err)}
	}

	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf("%s: %s", path, fmt.Sprintf(format, args...)))
	}

	if cl.displayName() == "" {
		fail("missing name or standard field")
	}
	if len(cl.Checks) == 0 {
		fail("no checks")
		return errs
	}

	// Unique IDs
	seen := make(map[string]int)
	for i, c := range cl.Checks {
		if c.ID == "" {
			fail("check[%d]: missing id", i)
			continue
		}
		if prev, ok := seen[c.ID]; ok {
			fail("check[%d]: duplicate id %q (first at check[%d])", i, c.ID, prev)
		}
		seen[c.ID] = i
	}

	// Declared total
	if cl.Total > 0 && cl.Total != len(cl.Checks) {
		fail("declared total %d but found %d checks", cl.Total, len(cl.Checks))
	}

	// Detect verdict-bearing: if ANY check has a verdict, the file is verdict-bearing
	verdictBearing := false
	for _, c := range cl.Checks {
		if c.Verdict != "" {
			verdictBearing = true
			break
		}
	}

	if verdictBearing {
		counts := make(map[string]int)
		for _, c := range cl.Checks {
			if c.Verdict == "" {
				fail("%s: missing verdict (file is verdict-bearing)", c.ID)
				continue
			}
			if !allowedVerdicts[c.Verdict] {
				fail("%s: invalid verdict %q", c.ID, c.Verdict)
				continue
			}
			counts[c.Verdict]++
			if c.Verdict == "EVIDENCE-GATED" && c.VerdictCondition == "" {
				fail("%s: EVIDENCE-GATED without verdict_condition", c.ID)
			}
			if c.Verdict == "GAP-AUTHOR" && c.VerdictReason == "" {
				fail("%s: GAP-AUTHOR without verdict_reason", c.ID)
			}
			if c.Verdict == "OOS" && c.VerdictReason == "" {
				fail("%s: OOS without verdict_reason", c.ID)
			}
		}

		total := 0
		for _, n := range counts {
			total += n
		}
		if total != len(cl.Checks) {
			fail("verdict partition incomplete: %d verdicts for %d checks", total, len(cl.Checks))
		}
	}

	return errs
}

func main() {
	dir := "data/frameworks"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob: %v\n", err)
		os.Exit(4)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no YAML files in %s\n", dir)
		os.Exit(2)
	}

	var allErrs []string
	for _, f := range files {
		allErrs = append(allErrs, validate(f)...)
	}

	if len(allErrs) > 0 {
		for _, e := range allErrs {
			fmt.Fprintln(os.Stderr, e)
		}
		fmt.Fprintf(os.Stderr, "\n%d violation(s) in %d file(s)\n", len(allErrs), len(files))
		os.Exit(1)
	}

	fmt.Printf("OK: %d checklist(s), %d file(s)\n", len(files), len(files))

	// Print per-file stats
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var cl checklist
		yaml.Unmarshal(data, &cl)
		base := filepath.Base(f)
		verdict := ""
		for _, c := range cl.Checks {
			if c.Verdict != "" {
				verdict = " (verdict-bearing)"
				break
			}
		}
		name := cl.displayName()
		if len(name) > 50 {
			name = name[:50]
		}
		name = strings.TrimSpace(name)
		fmt.Printf("  %-40s %3d checks%s\n", base, len(cl.Checks), verdict)
	}
}
