// Command genmethodologycoverage regenerates the per-(tool, domain)
// methodology-coverage markdown documents from the canonical sources:
// the embedded control catalog and the embedded inventory files at
// data/alternatives/*.yaml.
//
// One file per (tool, domain) is written under docs/, named
// methodology-coverage-{domain}-{tool}.md. The output carries a
// "generated — do not edit directly" header so the rendered tables stay
// in sync with the underlying YAML.
//
// Usage:
//
//	go run ./internal/tools/genmethodologycoverage          # write all docs
//	go run ./internal/tools/genmethodologycoverage -check   # exit 1 if stale
//	go run ./internal/tools/genmethodologycoverage -out docs   # custom dir
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	covadapter "github.com/sufield/stave/internal/adapters/coverage"
	"github.com/sufield/stave/internal/builtin/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	corecov "github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/kernel"
)

func main() {
	outDir := flag.String("out", "docs", "output directory")
	check := flag.Bool("check", false, "check mode: exit 1 if any output is stale")
	flag.Parse()

	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		exit("load controls: %v", err)
	}

	inventories, err := covadapter.LoadEmbedded()
	if err != nil {
		exit("load inventories: %v", err)
	}

	stale := false
	for _, inv := range inventories {
		filename := fmt.Sprintf("methodology-coverage-%s-%s.md", inv.Domain, inv.Tool)
		path := filepath.Join(*outDir, filename)
		body := renderDoc(inv, controls)

		if *check {
			existing, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(existing, body) {
				fmt.Fprintf(os.Stderr, "%s is stale. Run: go run ./internal/tools/genmethodologycoverage\n", path)
				stale = true
			}
			continue
		}

		if writeErr := os.WriteFile(path, body, 0o600); writeErr != nil {
			exit("write %s: %v", path, writeErr)
		}
		fmt.Printf("wrote %s\n", path)
	}

	if *check && stale {
		os.Exit(1)
	}
}

func exit(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

// row pairs an inventory check id with the Stave controls that cover it.
type row struct {
	checkID string
	covered []rowEntry
}

type rowEntry struct {
	controlID kernel.ControlID
	coverage  policy.CoverageStatus
	note      string
}

func renderDoc(inv corecov.ToolInventory, controls []policy.ControlDefinition) []byte {
	rows := buildRows(inv, controls)
	covered, partial, notCovered := summarize(rows)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s Coverage\n\n", titleCase(inv.Tool), strings.ToUpper(inv.Domain))
	b.WriteString("> **Generated file** — do not edit directly. This document is\n")
	b.WriteString("> regenerated from the embedded control catalog and the inventory at\n")
	fmt.Fprintf(&b, "> `data/alternatives/%s-%s.yaml` by `go run ./internal/tools/genmethodologycoverage`.\n\n", inv.Tool, inv.Domain)

	fmt.Fprintf(&b, "Cross-reference of %s's %d %s checks against Stave's %s control catalog.\n\n",
		titleCase(inv.Tool), len(inv.Checks), strings.ToUpper(inv.Domain), strings.ToUpper(inv.Domain))

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **%s %s checks surveyed:** %d\n", titleCase(inv.Tool), strings.ToUpper(inv.Domain), len(inv.Checks))
	fmt.Fprintf(&b, "- **COVERED:** %d\n", covered)
	fmt.Fprintf(&b, "- **PARTIAL:** %d\n", partial)
	fmt.Fprintf(&b, "- **NOT COVERED:** %d\n\n", notCovered)

	b.WriteString("## Coverage table\n\n")
	b.WriteString("| # | Alternative check | Stave status | Stave control(s) | Notes |\n")
	b.WriteString("|---|---|:---:|---|---|\n")
	for i, r := range rows {
		status, ids, notes := formatRow(r)
		fmt.Fprintf(&b, "| %d | `%s` | %s | %s | %s |\n", i+1, r.checkID, status, ids, notes)
	}

	b.WriteString("\n## Source\n\n")
	fmt.Fprintf(&b, "- Inventory: `data/alternatives/%s-%s.yaml`\n", inv.Tool, inv.Domain)
	b.WriteString("- Coverage annotations: `alternatives:` blocks on individual control YAMLs under `controls/`\n")

	return []byte(b.String())
}

// buildRows joins the inventory check list with the per-control
// alternatives annotations. Output is ordered to match the inventory
// declaration order so adding a check shows up at a stable position.
func buildRows(inv corecov.ToolInventory, controls []policy.ControlDefinition) []row {
	byCheck := make(map[string][]rowEntry)
	for i := range controls {
		ctl := &controls[i]
		for _, alt := range ctl.Alternatives {
			if alt.Tool != inv.Tool {
				continue
			}
			byCheck[alt.CheckID] = append(byCheck[alt.CheckID], rowEntry{
				controlID: ctl.ID,
				coverage:  alt.Coverage,
				note:      alt.Note,
			})
		}
	}
	for k := range byCheck {
		sort.Slice(byCheck[k], func(i, j int) bool {
			return byCheck[k][i].controlID < byCheck[k][j].controlID
		})
	}
	rows := make([]row, 0, len(inv.Checks))
	for _, id := range inv.Checks {
		rows = append(rows, row{checkID: id, covered: byCheck[id]})
	}
	return rows
}

// summarize counts how many inventory checks are covered, partial, or
// uncovered. A check is COVERED if any control fully covers it, PARTIAL
// if at least one control covers it but none does so fully, and NOT
// COVERED if no control references it.
func summarize(rows []row) (covered, partial, notCovered int) {
	for _, r := range rows {
		if len(r.covered) == 0 {
			notCovered++
			continue
		}
		anyFull := false
		for _, e := range r.covered {
			if e.coverage == policy.CoverageCovered {
				anyFull = true
				break
			}
		}
		if anyFull {
			covered++
		} else {
			partial++
		}
	}
	return covered, partial, notCovered
}

func formatRow(r row) (status, ids, notes string) {
	if len(r.covered) == 0 {
		return "NOT COVERED", "—", ""
	}
	anyFull := false
	for _, e := range r.covered {
		if e.coverage == policy.CoverageCovered {
			anyFull = true
			break
		}
	}
	if anyFull {
		status = "COVERED"
	} else {
		status = "PARTIAL"
	}
	idList := make([]string, len(r.covered))
	for i, e := range r.covered {
		idList[i] = "`" + string(e.controlID) + "`"
	}
	ids = strings.Join(idList, ", ")
	for _, e := range r.covered {
		if e.note != "" {
			notes = e.note
			break
		}
	}
	return status, ids, notes
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
