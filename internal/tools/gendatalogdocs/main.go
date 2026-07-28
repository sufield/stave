// Command gendatalogdocs extracts documented relations from Soufflé .dl
// files and generates a Markdown reference page. The .dl files are the
// single source of truth; the generated page cannot drift.
//
// Usage:
//
//	go run ./internal/tools/gendatalogdocs                # write docs/reference/datalog-relations.md
//	go run ./internal/tools/gendatalogdocs -check         # exit 1 if reference is stale
//	go run ./internal/tools/gendatalogdocs -out path      # custom output path
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type relation struct {
	Name   string
	Params string
	Doc    string
	Kind   string // "input", "output", "derived"
	Source string
	Rules  []string
}

type fileSection struct {
	Title string
	Rels  []relation
}

var (
	declRe   = regexp.MustCompile(`^\.decl\s+(\w+)\(([^)]*)\)`)
	inputRe  = regexp.MustCompile(`^\.input\s+(\w+)`)
	outputRe = regexp.MustCompile(`^\.output\s+(\w+)`)
	sepRe    = regexp.MustCompile(`^//\s*=====`)
)

func main() {
	check := flag.Bool("check", false, "Exit 1 if output is stale.")
	out := flag.String("out", "", "Output path (default: docs/reference/datalog-relations.md).")
	flag.Parse()

	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(root, "docs", "reference", "datalog-relations.md")
	}

	dlFiles := []struct {
		path    string
		section string
	}{
		{filepath.Join(root, "internal", "reasoning", "souffle", "iam", "schema.dl"), "Input Relations (schema.dl)"},
		{filepath.Join(root, "internal", "reasoning", "souffle", "iam", "rules.dl"), "Derived Relations (rules.dl)"},
		{filepath.Join(root, "internal", "reasoning", "souffle", "discovery", "discovery.dl"), "Discovery Relations (discovery.dl)"},
	}

	var sections []fileSection
	for _, df := range dlFiles {
		rels, err := parseFile(df.path, root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gendatalogdocs: %s: %v\n", df.path, err)
			os.Exit(1)
		}
		if len(rels) > 0 {
			sections = append(sections, fileSection{Title: df.section, Rels: rels})
		}
	}

	var buf bytes.Buffer
	render(&buf, sections)

	if *check {
		existing, err := os.ReadFile(outPath)
		if err != nil || !bytes.Equal(existing, buf.Bytes()) {
			fmt.Fprintf(os.Stderr, "gendatalogdocs: %s is stale — run: go run ./internal/tools/gendatalogdocs\n", outPath)
			os.Exit(1)
		}
		return
	}

	os.MkdirAll(filepath.Dir(outPath), 0o755)
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gendatalogdocs: write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d relations)\n", outPath, countRels(sections))
}

func parseFile(path, root string) ([]relation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	relPath, _ := filepath.Rel(root, path)
	lines := strings.Split(string(data), "\n")

	// First pass: collect .input and .output names.
	inputSet := map[string]bool{}
	outputSet := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := inputRe.FindStringSubmatch(trimmed); m != nil {
			inputSet[m[1]] = true
		}
		if m := outputRe.FindStringSubmatch(trimmed); m != nil {
			outputSet[m[1]] = true
		}
	}

	// Second pass: extract relations with doc comments.
	var rels []relation
	var pendingDoc []string
	inBlock := false

	for i := 0; i < len(lines); i++ { //nolint:rangeint // i is modified inside the loop
		trimmed := strings.TrimSpace(lines[i])

		// Separator lines toggle the block state.
		if sepRe.MatchString(trimmed) {
			if inBlock {
				// Closing separator — doc is ready for the next .decl.
				inBlock = false
			} else {
				// Opening separator — start collecting doc lines.
				inBlock = true
				pendingDoc = nil
			}
			continue
		}

		if inBlock {
			if text, ok := strings.CutPrefix(trimmed, "//"); ok {
				text = strings.TrimPrefix(text, " ")
				pendingDoc = append(pendingDoc, text)
			}
			continue
		}

		// Single-line doc comments outside a block (e.g., "// exfil_path: ...").
		if text, ok := strings.CutPrefix(trimmed, "//"); ok {
			text = strings.TrimPrefix(text, " ")
			if text != "" {
				pendingDoc = append(pendingDoc, text)
			}
			continue
		}

		// Handle multi-line .decl: join continuation lines until closing paren.
		declLine := trimmed
		if strings.HasPrefix(declLine, ".decl ") && !strings.Contains(declLine, ")") {
			for j := i + 1; j < len(lines); j++ {
				declLine += " " + strings.TrimSpace(lines[j])
				if strings.Contains(lines[j], ")") {
					i = j
					break
				}
			}
		}

		if m := declRe.FindStringSubmatch(declLine); m != nil {
			name := m[1]
			if strings.HasPrefix(name, "_") {
				pendingDoc = nil
				continue
			}

			kind := "derived"
			if inputSet[name] {
				kind = "input"
			} else if outputSet[name] {
				kind = "output"
			}

			var ruleLines []string
			for j := i + 1; j < len(lines); j++ {
				rt := strings.TrimSpace(lines[j])
				if rt == "" {
					continue
				}
				if strings.HasPrefix(rt, ".") || strings.HasPrefix(rt, "//") || sepRe.MatchString(rt) {
					break
				}
				ruleLines = append(ruleLines, lines[j])
			}

			rels = append(rels, relation{
				Name:   name,
				Params: m[2],
				Doc:    cleanDoc(pendingDoc),
				Kind:   kind,
				Source: relPath,
				Rules:  ruleLines,
			})
			pendingDoc = nil
		}

		if trimmed != "" && !strings.HasPrefix(trimmed, ".") {
			pendingDoc = nil
		}
	}

	return rels, nil
}

func cleanDoc(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	return strings.Join(lines, "\n")
}

func render(buf *bytes.Buffer, sections []fileSection) {
	fmt.Fprintln(buf, "# Datalog Relations Reference")
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "Auto-generated from `.dl` source files. Do not edit manually.")
	fmt.Fprintln(buf, "Run: `go run ./internal/tools/gendatalogdocs`")
	fmt.Fprintln(buf)

	for _, sec := range sections {
		fmt.Fprintf(buf, "## %s\n\n", sec.Title)
		fmt.Fprintln(buf, "| Relation | Parameters | Kind | Description |")
		fmt.Fprintln(buf, "|----------|-----------|------|-------------|")
		for _, r := range sec.Rels {
			desc := firstSentence(r.Doc)
			fmt.Fprintf(buf, "| [`%s`](#%s) | `%s` | %s | %s |\n",
				r.Name, strings.ToLower(r.Name), formatParams(r.Params), r.Kind, desc)
		}
		fmt.Fprintln(buf)
	}

	fmt.Fprintln(buf, "---")
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "## Relation Details")
	fmt.Fprintln(buf)

	for _, sec := range sections {
		for _, r := range sec.Rels {
			fmt.Fprintf(buf, "### %s\n\n", r.Name)
			fmt.Fprintf(buf, "**Source:** `%s`\n\n", r.Source)
			fmt.Fprintf(buf, "**Kind:** %s\n\n", r.Kind)
			fmt.Fprintf(buf, "```datalog\n.decl %s(%s)\n```\n\n", r.Name, r.Params)

			if r.Doc != "" {
				fmt.Fprintln(buf, r.Doc)
				fmt.Fprintln(buf)
			}

			if len(r.Rules) > 0 && r.Kind != "input" {
				fmt.Fprintln(buf, "**Rules:**")
				fmt.Fprintln(buf)
				fmt.Fprintln(buf, "```datalog")
				for _, rl := range r.Rules {
					fmt.Fprintln(buf, rl)
				}
				fmt.Fprintln(buf, "```")
				fmt.Fprintln(buf)
			}
		}
	}
}

func firstSentence(doc string) string {
	if doc == "" {
		return ""
	}
	line := strings.SplitN(doc, "\n", 2)[0]
	if idx := strings.Index(line, " — "); idx >= 0 {
		line = line[idx+len(" — "):]
	}
	if len(line) > 120 {
		line = line[:117] + "..."
	}
	return strings.TrimRight(line, ".")
}

func formatParams(params string) string {
	return strings.TrimSpace(strings.ReplaceAll(params, "  ", " "))
}

func countRels(sections []fileSection) int {
	n := 0
	for _, s := range sections {
		n += len(s.Rels)
	}
	return n
}
