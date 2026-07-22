// Command gencommanddocs generates the CLI command reference from the
// live cobra command tree — the single source of truth is the binary's
// own command wiring, so the doc cannot drift from the actual commands.
//
// Usage:
//
//	go run ./internal/tools/gencommanddocs           # write docs/command-reference.md
//	go run ./internal/tools/gencommanddocs -check    # exit 1 if the reference is stale
//	go run ./internal/tools/gencommanddocs -out path # custom output path
//
// Descriptions come from each command's cobra `Short`, which is already
// maintained per-command. Un-derivable curated columns (Input / Output /
// "when to use") are intentionally not emitted — keeping the generated
// doc to what the tree actually knows is what makes it drift-proof.
package main

import (
	"bytes"
	"cmp"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd"
)

func main() {
	outPath := flag.String("out", "docs/command-reference.md", "output file for the generated command reference")
	check := flag.Bool("check", false, "check mode: exit 1 if the command reference is stale")
	catalog := flag.String("catalog", "", "generate the curated when-to-use catalog (from catalog_meta.go annotations) to this path")
	catalogCheck := flag.String("catalog-check", "", "verify the curated catalog at this path is in sync with the annotations + binary")
	site := flag.String("site", "", "generate Docusaurus CLI reference pages into this directory")
	siteCheck := flag.String("site-check", "", "verify the site CLI reference pages are in sync with the binary")
	flag.Parse()

	app, err := cmd.NewApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: wire CLI: %v\n", err)
		os.Exit(1)
	}

	// Curated-catalog modes: generate or check commands-catalog.md from the
	// annotation data + the live cobra tree.
	if *catalog != "" || *catalogCheck != "" {
		buf, err := renderCatalog(app.Root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if *catalogCheck != "" {
			existing, readErr := os.ReadFile(*catalogCheck)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", readErr)
				os.Exit(1)
			}
			if !bytes.Equal(existing, buf.Bytes()) {
				fmt.Fprintf(os.Stderr, "%s is stale. Run: make docs-commands-catalog\n", *catalogCheck)
				os.Exit(1)
			}
			fmt.Printf("%s: in sync\n", *catalogCheck)
			return
		}
		if err := os.WriteFile(*catalog, buf.Bytes(), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", *catalog, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d annotated commands)\n", *catalog, len(catalogAnnotations))
		return
	}

	// Site mode: generate or check Docusaurus CLI reference pages.
	if *site != "" || *siteCheck != "" {
		if *siteCheck != "" {
			if err := checkSite(app.Root, *siteCheck); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			fmt.Printf("%s: in sync\n", *siteCheck)
			return
		}
		n, err := renderSite(app.Root, *site)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %d pages to %s\n", n, *site)
		return
	}

	buf, total := render(app.Root)

	if *check {
		existing, readErr := os.ReadFile(*outPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", readErr)
			os.Exit(1)
		}
		if !bytes.Equal(existing, buf.Bytes()) {
			fmt.Fprintf(os.Stderr, "%s is stale. Run: make docs-commands\n", *outPath)
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*outPath, buf.Bytes(), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d commands)\n", *outPath, total)
}

// renderCatalog generates the curated when-to-use catalog
// (commands-catalog.md) from the annotation data in catalog_meta.go
// joined with the live cobra tree. The Purpose column comes from each
// command's cobra Short — never stored in the annotations — so it cannot
// drift. Returns an error (without writing) when the annotations and the
// binary disagree, enforcing the same invariants that let the catalog rot:
//   - no phantom: every annotated path must be a real command.
//   - no missing leaf: every leaf command must be annotated. Bare
//     parent/group commands may be annotated but are not required.
func renderCatalog(root *cobra.Command) (*bytes.Buffer, error) {
	all, leaves := collectPaths(root)
	short := shortByPath(root)

	annotated := map[string]struct{}{}
	var phantom []string
	for _, a := range catalogAnnotations {
		annotated[a.Path] = struct{}{}
		if _, ok := all[a.Path]; !ok {
			phantom = append(phantom, a.Path)
		}
	}
	var missing []string
	for c := range leaves {
		if _, ok := annotated[c]; !ok {
			missing = append(missing, c)
		}
	}
	slices.Sort(phantom)
	slices.Sort(missing)
	if len(phantom) > 0 || len(missing) > 0 {
		var b strings.Builder
		b.WriteString("catalog annotations are out of sync with the binary:\n")
		for _, c := range phantom {
			fmt.Fprintf(&b, "  phantom (remove from catalog_meta.go): %s\n", c)
		}
		for _, c := range missing {
			fmt.Fprintf(&b, "  missing  (add to catalog_meta.go):       %s\n", c)
		}
		return nil, fmt.Errorf("%s", b.String())
	}

	var buf bytes.Buffer
	buf.WriteString("# Stave Commands — When to Reach for Each\n\n")
	buf.WriteString("<!-- GENERATED by internal/tools/gencommanddocs from\n")
	buf.WriteString("     catalog_meta.go (annotations) + the live cobra tree. DO NOT EDIT.\n")
	buf.WriteString("     Regenerate with `make docs-commands-catalog`. Edit the when-to-use\n")
	buf.WriteString("     text or grouping in internal/tools/gencommanddocs/catalog_meta.go. -->\n\n")
	buf.WriteString("Authoritative command inventory: `stave/docs/command-reference.md`\n")
	buf.WriteString("(also generated). This is the curated *when-to-use* companion. Purpose\n")
	buf.WriteString("comes from each command's `--help` summary; run `stave <command> --help`\n")
	buf.WriteString("for full flags and exit codes.\n")

	for _, group := range catalogGroupOrder {
		rows := annotationsForGroup(group)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&buf, "\n## %s\n\n", group)
		buf.WriteString("| Command | Purpose | When to use |\n|---|---|---|\n")
		for _, a := range rows {
			fmt.Fprintf(&buf, "| `%s` | %s | %s |\n",
				a.Path, escapePipes(short[a.Path]), escapePipes(a.When))
		}
	}

	return &buf, nil
}

// annotationsForGroup returns the annotations in the given group,
// preserving catalogAnnotations slice order (editorial ordering).
func annotationsForGroup(group string) []catalogAnnotation {
	var out []catalogAnnotation
	for _, a := range catalogAnnotations {
		if a.Group == group {
			out = append(out, a)
		}
	}
	return out
}

// shortByPath maps every command path to its cobra Short.
func shortByPath(root *cobra.Command) map[string]string {
	m := map[string]string{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if skip(sub) {
				continue
			}
			m[commandPath(sub)] = sub.Short
			walk(sub)
		}
	}
	walk(root)
	return m
}

// collectPaths walks the tree and returns the set of all command paths
// and the subset that are leaves (no non-skipped subcommands).
func collectPaths(root *cobra.Command) (all, leaves map[string]struct{}) {
	all, leaves = map[string]struct{}{}, map[string]struct{}{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if skip(sub) {
				continue
			}
			p := commandPath(sub)
			all[p] = struct{}{}
			hasChild := false
			for _, g := range sub.Commands() {
				if !skip(g) {
					hasChild = true
					break
				}
			}
			if !hasChild {
				leaves[p] = struct{}{}
			}
			walk(sub)
		}
	}
	walk(root)
	return all, leaves
}

// entry is one command row: its full invocation path and cobra Short.
type entry struct {
	path  string
	short string
}

// categoryOrder controls the section display order in the output.
var categoryOrder = []string{
	"Getting Started",
	"Control Engine",
	"Workflow & CI",
	"Security Analysis",
	"Compliance & Evidence",
	"Risk Acceptance",
	"Control Authoring",
	"Catalog & Coverage",
	"Templates & Packs",
	"Snapshot & Transform",
	"Interop & Export",
	"Environment & Config",
	"Project Management",
}

// categoryPrefix maps a command path prefix to a category. Sorted by
// prefix length descending at init time so longer (more specific)
// prefixes match before shorter ones.
var categoryPrefixes = []struct {
	prefix   string
	category string
}{
	{"forge chain", "Control Authoring"},
	{"forge", "Control Authoring"},
	{"controls", "Control Authoring"},
	{"exempt", "Risk Acceptance"},
	{"permissions", "Security Analysis"},
	{"inspect", "Security Analysis"},
	{"ci baseline", "Workflow & CI"},
	{"ci fix", "Workflow & CI"},
	{"ci gate", "Workflow & CI"},
	{"ci diff", "Workflow & CI"},
	{"ci", "Workflow & CI"},
	{"snapshot", "Workflow & CI"},
	{"catalog", "Catalog & Coverage"},
	{"capabilities catalog", "Catalog & Coverage"},
	{"capabilities", "Catalog & Coverage"},
	{"template", "Templates & Packs"},
	{"pack", "Templates & Packs"},
	{"packs", "Templates & Packs"},
	{"recommend", "Templates & Packs"},
	{"profile", "Compliance & Evidence"},
	{"compliance", "Compliance & Evidence"},
	{"compare", "Compliance & Evidence"},
	{"bundle", "Compliance & Evidence"},
	{"trend", "Compliance & Evidence"},
	{"report", "Compliance & Evidence"},
	{"export compliance", "Compliance & Evidence"},
	{"export ocsf", "Compliance & Evidence"},
	{"export oscal", "Compliance & Evidence"},
	{"export tickets", "Compliance & Evidence"},
	{"export changes", "Compliance & Evidence"},
	{"export-controls", "Interop & Export"},
	{"export-sir", "Interop & Export"},
	{"export", "Compliance & Evidence"},
	{"graph", "Interop & Export"},
	{"cel", "Interop & Export"},
	{"render", "Interop & Export"},
	{"metrics", "Interop & Export"},
	{"telemetry", "Interop & Export"},
	{"enforce", "Interop & Export"},
	{"attest", "Snapshot & Transform"},
	{"fingerprint", "Snapshot & Transform"},
	{"transform", "Snapshot & Transform"},
	{"sanitize", "Snapshot & Transform"},
	{"diff", "Snapshot & Transform"},
	{"validate-mapping", "Snapshot & Transform"},
	{"config", "Environment & Config"},
	{"completion", "Environment & Config"},
	{"doctor", "Environment & Config"},
	{"version", "Environment & Config"},
	{"contract", "Environment & Config"},
	{"schemas", "Environment & Config"},
	{"features", "Environment & Config"},
	{"generate", "Getting Started"},
	{"apply", "Control Engine"},
	{"diagnose", "Control Engine"},
	{"expand", "Control Engine"},
	{"explain", "Control Engine"},
	{"validate", "Control Engine"},
	{"prove", "Security Analysis"},
	{"score", "Security Analysis"},
	{"scorecard", "Security Analysis"},
	{"search", "Security Analysis"},
	{"path", "Security Analysis"},
	{"bisect", "Workflow & CI"},
	{"check", "Workflow & CI"},
	{"status", "Workflow & CI"},
	{"alias", "Project Management"},
	{"lint", "Control Authoring"},
	{"fmt", "Control Authoring"},
	{"coverage", "Catalog & Coverage"},
	{"gaps", "Catalog & Coverage"},
	{"readiness", "Catalog & Coverage"},
	{"map", "Catalog & Coverage"},
	{"discover", "Catalog & Coverage"},
	{"plan", "Catalog & Coverage"},
	{"test", "Control Authoring"},
	{"toolmap", "Security Analysis"},
}

func init() {
	slices.SortFunc(categoryPrefixes, func(a, b struct {
		prefix   string
		category string
	}) int {
		return cmp.Compare(len(b.prefix), len(a.prefix))
	})
}

// categorize returns the category for a command path using longest-prefix match.
func categorize(path string) string {
	for _, cp := range categoryPrefixes {
		if path == cp.prefix || strings.HasPrefix(path, cp.prefix+" ") {
			return cp.category
		}
	}
	return "Uncategorized"
}

// render walks the tree and produces the markdown reference plus the
// total command count. Output is deterministic: categories follow
// categoryOrder, and commands within a category are sorted by full path.
func render(root *cobra.Command) (*bytes.Buffer, int) {
	byCategory := map[string][]entry{}
	total := 0
	var uncategorized []string

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if skip(sub) {
				continue
			}
			p := commandPath(sub)
			cat := categorize(p)
			if cat == "Uncategorized" {
				uncategorized = append(uncategorized, p)
			}
			byCategory[cat] = append(byCategory[cat], entry{path: p, short: sub.Short})
			total++
			walk(sub)
		}
	}
	walk(root)

	if len(uncategorized) > 0 {
		slices.Sort(uncategorized)
		fmt.Fprintf(os.Stderr, "WARNING: %d uncategorized commands (add to categoryPrefixes):\n", len(uncategorized))
		for _, p := range uncategorized {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
	}

	groupCount := 0
	for _, cat := range categoryOrder {
		if len(byCategory[cat]) > 0 {
			groupCount++
		}
	}
	if len(byCategory["Uncategorized"]) > 0 {
		groupCount++
	}

	var buf bytes.Buffer
	buf.WriteString("# Command Reference\n\n")
	buf.WriteString("<!-- GENERATED by internal/tools/gencommanddocs — DO NOT EDIT.\n")
	buf.WriteString("     Regenerate with `make docs-commands`. Source of truth: the\n")
	buf.WriteString("     cobra command tree in the stave binary (prod edition). -->\n\n")
	buf.WriteString("All commands ship in the standard `stave` binary. No build tags are\n")
	buf.WriteString("required. Descriptions are each command's one-line summary; run\n")
	buf.WriteString("`stave <command> --help` for full usage, flags, and exit codes.\n\n")
	fmt.Fprintf(&buf, "_%d commands across %d groups._\n", total, groupCount)

	for _, cat := range categoryOrder {
		entries := byCategory[cat]
		if len(entries) == 0 {
			continue
		}
		slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.path, b.path) })
		fmt.Fprintf(&buf, "\n## %s\n\n", cat)
		buf.WriteString("| Command | Description |\n|---|---|\n")
		for _, e := range entries {
			fmt.Fprintf(&buf, "| `%s` | %s |\n", e.path, escapePipes(e.short))
		}
	}

	// Uncategorized at the end — should be empty if all commands are mapped.
	if entries := byCategory["Uncategorized"]; len(entries) > 0 {
		slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.path, b.path) })
		fmt.Fprintf(&buf, "\n## Uncategorized\n\n")
		buf.WriteString("| Command | Description |\n|---|---|\n")
		for _, e := range entries {
			fmt.Fprintf(&buf, "| `%s` | %s |\n", e.path, escapePipes(e.short))
		}
	}

	return &buf, total
}

// commandPath returns the invocation path without the root name, e.g.
// "ci baseline check".
func commandPath(c *cobra.Command) string {
	full := c.CommandPath() // "stave ci baseline check"
	return strings.TrimPrefix(full, c.Root().Name()+" ")
}

// skip drops hidden commands and cobra's auto-generated help command.
func skip(c *cobra.Command) bool {
	return c.Hidden || c.Name() == "help"
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
