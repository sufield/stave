package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// siteChild is a subcommand reference for the parent page.
type siteChild struct {
	path  string
	short string
}

// siteEntry holds everything needed to render one Docusaurus page.
type siteEntry struct {
	slug     string // e.g. "stave-apply" or "stave-ci-baseline-check"
	cmdPath  string // e.g. "apply" or "ci baseline check"
	short    string
	long     string
	usage    string
	example  string
	flags    string
	children []siteChild
}

// renderSite generates Docusaurus CLI reference pages into dir.
// Returns the number of command pages written.
func renderSite(root *cobra.Command, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}

	entries := collectSiteEntries(root)

	// Write _category_.json
	catJSON := `{
  "label": "CLI Reference",
  "position": 5,
  "link": {
    "type": "doc",
    "id": "reference/cli-reference/_index"
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "_category_.json"), []byte(catJSON), 0o600); err != nil {
		return 0, fmt.Errorf("write _category_.json: %w", err)
	}

	// Write _index.md — overview with full command table.
	idx := renderSiteIndex(entries)
	if err := os.WriteFile(filepath.Join(dir, "_index.md"), idx, 0o600); err != nil {
		return 0, fmt.Errorf("write _index.md: %w", err)
	}

	// Write one page per command.
	for i, e := range entries {
		page := renderSitePage(e, i+2) // sidebar_position: 2,3,4,...
		path := filepath.Join(dir, e.slug+".md")
		if err := os.WriteFile(path, page, 0o600); err != nil {
			return 0, fmt.Errorf("write %s: %w", e.slug, err)
		}
	}

	return len(entries), nil
}

// checkSite verifies that the generated site pages match what's on disk.
func checkSite(root *cobra.Command, dir string) error {
	entries := collectSiteEntries(root)

	// Build the expected file set with content hashes.
	expected := map[string][]byte{}

	catJSON := `{
  "label": "CLI Reference",
  "position": 5,
  "link": {
    "type": "doc",
    "id": "reference/cli-reference/_index"
  }
}
`
	expected["_category_.json"] = []byte(catJSON)
	expected["_index.md"] = renderSiteIndex(entries)
	for i, e := range entries {
		expected[e.slug+".md"] = renderSitePage(e, i+2)
	}

	// Check each expected file exists with matching content.
	var stale []string
	for name, want := range expected {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			stale = append(stale, name+" (missing)")
			continue
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			stale = append(stale, name+" (content differs)")
		}
	}

	// Check for unexpected files (stale pages for removed commands).
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, de := range dirEntries {
		if de.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if _, ok := expected[de.Name()]; !ok {
			stale = append(stale, de.Name()+" (unexpected — remove)")
		}
	}

	if len(stale) > 0 {
		slices.Sort(stale)
		return fmt.Errorf("%s is stale (%d files):\n  %s\nRun: make docs-site",
			dir, len(stale), strings.Join(stale, "\n  "))
	}
	return nil
}

func collectSiteEntries(root *cobra.Command) []siteEntry {
	var entries []siteEntry
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if skip(sub) {
				continue
			}
			e := siteEntry{
				slug:    slugFor(sub),
				cmdPath: commandPath(sub),
				short:   sub.Short,
				long:    sub.Long,
				usage:   sub.UseLine(),
				example: sub.Example,
				flags:   localFlagUsages(sub),
			}
			for _, child := range sub.Commands() {
				if !skip(child) {
					e.children = append(e.children, siteChild{
						path:  commandPath(child),
						short: child.Short,
					})
				}
			}
			entries = append(entries, e)
			walk(sub)
		}
	}
	walk(root)
	slices.SortFunc(entries, func(a, b siteEntry) int {
		return strings.Compare(a.cmdPath, b.cmdPath)
	})
	return entries
}

func slugFor(c *cobra.Command) string {
	return "stave-" + strings.ReplaceAll(commandPath(c), " ", "-")
}

func localFlagUsages(c *cobra.Command) string {
	var buf bytes.Buffer
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		shorthand := ""
		if f.Shorthand != "" {
			shorthand = fmt.Sprintf("-%s, ", f.Shorthand)
		}
		defVal := ""
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "[]" {
			defVal = fmt.Sprintf(" (default: `%s`)", f.DefValue)
		}
		fmt.Fprintf(&buf, "| `%s--%s` | %s | %s%s |\n",
			shorthand, f.Name, f.Value.Type(), escapePipes(f.Usage), defVal)
	})
	return buf.String()
}

func renderSiteIndex(entries []siteEntry) []byte {
	var buf bytes.Buffer
	buf.WriteString(`---
title: "CLI Reference"
sidebar_label: "Overview"
sidebar_position: 1
slug: /reference/cli-reference
description: "Complete reference for all Stave CLI commands."
---

<!-- GENERATED by internal/tools/gencommanddocs — DO NOT EDIT.
     Regenerate with: make docs-site -->

# CLI Reference

Complete reference for all Stave commands. Run ` + "`stave <command> --help`" + ` for
full usage, flags, and exit codes.

`)
	fmt.Fprintf(&buf, "_%d commands._\n\n", len(entries))
	buf.WriteString("| Command | Description |\n|---|---|\n")
	for _, e := range entries {
		fmt.Fprintf(&buf, "| [`stave %s`](%s.md) | %s |\n",
			e.cmdPath, e.slug, escapePipes(e.short))
	}

	buf.WriteString(`
## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Security-audit gating failure |
| 2 | Invalid input or validation failure |
| 3 | Violations found (apply) or diagnostics found (diagnose) |
| 4 | Internal error |
| 130 | Interrupted (SIGINT) |
`)
	return buf.Bytes()
}

func renderSitePage(e siteEntry, pos int) []byte {
	var buf bytes.Buffer

	// Frontmatter
	label := strings.TrimPrefix(e.cmdPath, "stave ")
	fmt.Fprintf(&buf, `---
title: "stave %s"
sidebar_label: "%s"
sidebar_position: %d
description: "%s"
---

`, e.cmdPath, label, pos, escapeFrontmatter(e.short))

	// Title
	fmt.Fprintf(&buf, "# stave %s\n\n", e.cmdPath)

	// Short description
	fmt.Fprintf(&buf, "%s\n\n", e.short)

	// Usage
	fmt.Fprintf(&buf, "## Usage\n\n```\n%s\n```\n\n", e.usage)

	// Description (Long)
	if e.long != "" {
		buf.WriteString("## Description\n\n")
		buf.WriteString(e.long)
		buf.WriteString("\n\n")
	}

	// Flags
	if e.flags != "" {
		buf.WriteString("## Flags\n\n")
		buf.WriteString("| Flag | Type | Description |\n|---|---|---|\n")
		buf.WriteString(e.flags)
		buf.WriteString("\n")
	}

	// Subcommands
	if len(e.children) > 0 {
		buf.WriteString("## Subcommands\n\n")
		buf.WriteString("| Command | Description |\n|---|---|\n")
		for _, child := range e.children {
			childSlug := "stave-" + strings.ReplaceAll(child.path, " ", "-")
			fmt.Fprintf(&buf, "| [`stave %s`](%s.md) | %s |\n", child.path, childSlug, escapePipes(child.short))
		}
		buf.WriteString("\n")
	}

	// Examples
	if e.example != "" {
		buf.WriteString("## Examples\n\n```bash\n")
		buf.WriteString(strings.TrimSpace(e.example))
		buf.WriteString("\n```\n")
	}

	return buf.Bytes()
}

func escapeFrontmatter(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
