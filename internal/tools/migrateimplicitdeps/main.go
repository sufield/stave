// Command migrateimplicitdeps populates implicit_dependencies on all
// chain YAMLs that don't already have the field. It reads each chain's
// member controls, looks them up in the implicit dependency registry,
// and appends the appropriate YAML block.
//
// Usage:
//
//	go run ./internal/tools/migrateimplicitdeps
//	go run ./internal/tools/migrateimplicitdeps -dry-run
//	go run ./internal/tools/migrateimplicitdeps -dir chains/
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/app/chainforge"
	"github.com/sufield/stave/internal/core/kernel"
)

// chainStub is the minimal structure needed to extract controls.
type chainStub struct {
	ID       string   `yaml:"id"`
	Controls []string `yaml:"controls"`
}

func main() {
	dir := flag.String("dir", "chains", "chain YAML directory")
	dryRun := flag.Bool("dry-run", false, "preview changes without writing")
	flag.Parse()

	files, err := filepath.Glob(filepath.Join(*dir, "*.yaml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: glob: %v\n", err)
		os.Exit(1)
	}

	var (
		skipped  int
		updated  int
		empty    int
		errCount int
	)

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: read %s: %v\n", path, err)
			errCount++
			continue
		}

		content := string(data)

		if strings.Contains(content, "implicit_dependencies") {
			skipped++
			continue
		}

		var stub chainStub
		if err := yaml.Unmarshal(data, &stub); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: parse %s: %v\n", path, err)
			errCount++
			continue
		}

		ctlIDs := make([]kernel.ControlID, len(stub.Controls))
		for i, c := range stub.Controls {
			ctlIDs[i] = kernel.ControlID(c)
		}

		deps := chainforge.ChainDeps(ctlIDs)

		content = strings.TrimRight(content, "\n") + "\n"

		if len(deps) == 0 {
			content += "implicit_dependencies: []\n"
			empty++
		} else {
			content += "implicit_dependencies:\n"
			for _, dep := range deps {
				content += fmt.Sprintf("  - source: %s\n", dep.Source)
				content += fmt.Sprintf("    fallback: %s\n", dep.Fallback)
				content += "    diagnostic: >-\n"
				content += fmt.Sprintf("      %s\n", dep.Diagnostic)
			}
			updated++
		}

		if *dryRun {
			fmt.Printf("%s: %s → %d deps\n", filepath.Base(path), stub.ID, len(deps))
			continue
		}

		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: write %s: %v\n", path, err)
			errCount++
			continue
		}
	}

	fmt.Printf("chains: %d total, %d skipped (already have field), %d updated (with deps), %d updated (empty), %d errors\n",
		len(files), skipped, updated, empty, errCount)

	if errCount > 0 {
		os.Exit(1)
	}
}
