// Command compliance-diff takes a compliance framework YAML checklist,
// normalizes it, and diffs against the Stave control catalog.
//
// Usage:
//
//	go run ./internal/tools/compliance-diff --framework data/frameworks/cis-aws-v3.yaml
//	go run ./internal/tools/compliance-diff --all
//	go run ./internal/tools/compliance-diff --framework data/frameworks/cis-aws-v3.yaml --gaps-only
//	go run ./internal/tools/compliance-diff --framework data/frameworks/cis-aws-v3.yaml --json
//	go run ./internal/tools/compliance-diff --all --summary
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/adapters/compliance"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
)

const frameworkDir = "data/frameworks"

func main() {
	framework := flag.String("framework", "", "path to framework YAML file")
	all := flag.Bool("all", false, "run against all frameworks in "+frameworkDir)
	gapsOnly := flag.Bool("gaps-only", false, "only show gaps")
	summary := flag.Bool("summary", false, "one-line-per-framework summary (with --all)")
	jsonOut := flag.Bool("json", false, "output as JSON")
	flag.Parse()

	if !*all && *framework == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./internal/tools/compliance-diff --framework <path>")
		fmt.Fprintln(os.Stderr, "       go run ./internal/tools/compliance-diff --all [--summary]")
		os.Exit(2)
	}

	catalog := loadCatalog()
	matcher := newMatcher(catalog)

	if *all {
		paths, err := discoverFrameworks(frameworkDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(paths) == 0 {
			fmt.Fprintf(os.Stderr, "no framework files in %s\n", frameworkDir)
			os.Exit(1)
		}

		var reports []DiffReport
		for _, p := range paths {
			fw, err := compliance.ParseFramework(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skip %s: %v\n", p, err)
				continue
			}
			reports = append(reports, matcher.diff(fw))
		}

		if *jsonOut {
			writeJSON(reports)
		} else if *summary {
			writeSummaryTable(reports)
		} else {
			for i, r := range reports {
				if i > 0 {
					fmt.Println()
				}
				writeTextReport(r, *gapsOnly)
			}
		}
		return
	}

	fw, err := compliance.ParseFramework(*framework)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report := matcher.diff(fw)
	if *jsonOut {
		writeJSON(report)
	} else {
		writeTextReport(report, *gapsOnly)
	}
}

func loadCatalog() *policy.Catalog {
	registry := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := registry.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load catalog: %v\n", err)
		os.Exit(1)
	}
	return policy.NewCatalog(controls)
}

func discoverFrameworks(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	return paths, nil
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
