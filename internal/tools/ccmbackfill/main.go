//go:build ignore

// Command ccmbackfill inserts compliance.ccm_v4 mappings into Stave control
// YAML files using the inference rules in this package.
//
// Usage:
//
//	go run ./internal/tools/ccmbackfill/main.go \
//	    -controls ./controls \
//	    -report ./ccm-coverage-report.md \
//	    -apply
//
// Without -apply, the tool prints a report but leaves files unchanged.
// The apply path uses a surgical text patch: it parses the YAML only to
// locate the compliance: block's line range, then edits those lines in
// place. This keeps diffs small and preserves existing block-scalar
// formatting, indentation, and comments throughout the rest of the file.
package main

import (
	"bytes"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/tools/ccmbackfill"
)

type controlRec struct {
	Path string
	Rel  string
	ID   string
	Dir  string
	CCMs []string
}

func main() {
	var (
		root   string
		report string
		apply  bool
	)
	flag.StringVar(&root, "controls", "controls", "path to controls root (containing service dirs)")
	flag.StringVar(&report, "report", "", "path to write coverage report markdown; empty prints to stdout")
	flag.BoolVar(&apply, "apply", false, "apply mappings to YAML files (destructive)")
	flag.Parse()

	records, err := walkControls(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	for i := range records {
		records[i].CCMs = ccmbackfill.Infer(records[i].Dir, records[i].ID)
	}

	if apply {
		applied := 0
		for _, r := range records {
			if len(r.CCMs) == 0 {
				continue
			}
			changed, err := applyToFile(r.Path, r.CCMs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "apply %s: %v\n", r.Path, err)
				os.Exit(1)
			}
			if changed {
				applied++
			}
		}
		fmt.Fprintf(os.Stderr, "applied mappings to %d files\n", applied)
	}

	reportText := renderReport(records)
	if report == "" {
		fmt.Print(reportText)
	} else {
		if err := os.WriteFile(report, []byte(reportText), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote report to %s\n", report)
	}
}

func walkControls(root string) ([]controlRec, error) {
	var recs []controlRec
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		dir := filepath.ToSlash(filepath.Dir(rel))
		id, err := readControlID(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		recs = append(recs, controlRec{
			Path: path,
			Rel:  rel,
			ID:   id,
			Dir:  dir,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(recs, func(a, b controlRec) int { return cmp.Compare(a.ID, b.ID) })
	return recs, nil
}

func readControlID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var partial struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(data, &partial); err != nil {
		return "", err
	}
	return partial.ID, nil
}

// ccmLine renders the canonical ccm_v4 line (flow-style, quoted IDs).
// Indentation prefix is added by the caller.
func ccmLine(ccms []string) string {
	quoted := make([]string, len(ccms))
	for i, c := range ccms {
		quoted[i] = `"` + c + `"`
	}
	return "ccm_v4: [" + strings.Join(quoted, ", ") + "]"
}

// applyToFile inserts (or replaces) the compliance.ccm_v4 entry in path
// with the given CCM IDs. Returns whether the file was modified.
//
// Strategy:
//   - If a `compliance:` block exists: append or replace `ccm_v4: [...]`
//     at the block's indent.
//   - If no compliance block exists: insert a new `compliance:\n  ccm_v4: [...]`
//     after the first top-level `description:` key (respecting any
//     multi-line block-scalar form it takes).
//
// The tool reads the YAML once via yaml.Node to discover the line
// number of the compliance block and its child indent. It never
// re-serialises the whole document.
func applyToFile(path string, ccms []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false, errors.New("unexpected YAML structure")
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return false, errors.New("top-level YAML is not a mapping")
	}

	complianceKey, complianceVal := findChild(top, "compliance")

	lines := splitLines(data)

	if complianceKey != nil && complianceVal != nil && complianceVal.Kind == yaml.MappingNode {
		// Flow-style or empty mappings (`compliance: {}`) have no child
		// lines to anchor against; replace the whole `compliance:` line
		// with a fresh block-form entry.
		if complianceVal.Style == yaml.FlowStyle || len(complianceVal.Content) == 0 {
			return replaceSingleLineCompliance(path, lines, complianceKey, ccms)
		}
		return patchExistingCompliance(path, lines, complianceKey, complianceVal, ccms)
	}

	// No compliance block (or compliance exists but isn't a mapping — treat
	// as "no usable block" and insert a fresh one). Insert after description.
	descKey, descVal := findChild(top, "description")
	if descKey == nil {
		// Fall back to inserting right after the first top-level key's value.
		return false, fmt.Errorf("control %s has no description key to anchor insertion", path)
	}
	return insertNewCompliance(path, lines, descKey, descVal, ccms)
}

func patchExistingCompliance(path string, lines []string, key, val *yaml.Node, ccms []string) (bool, error) {
	// Determine indent from an existing child key's column (YAML columns
	// are 1-based). yaml.v3 tracks Line/Column on each Node.
	childIndent := childIndentOfMapping(val)
	if childIndent < 0 {
		// Compliance block is empty (`compliance: {}`). Use key column + 2.
		childIndent = key.Column + 1 // 0-based
	}
	indentStr := strings.Repeat(" ", childIndent)
	newLine := indentStr + ccmLine(ccms)

	// Find any existing ccm_v4 child under compliance.
	ccmChildIdx := -1
	for i := 0; i+1 < len(val.Content); i += 2 {
		if val.Content[i].Value == "ccm_v4" {
			ccmChildIdx = i
			break
		}
	}

	if ccmChildIdx >= 0 {
		ccmKeyNode := val.Content[ccmChildIdx]
		startLine := ccmKeyNode.Line - 1 // 0-based
		endLine := walkPastChildrenOf(ccmKeyNode.Column, ccmKeyNode.Line, lines)
		newLines := replaceLineRange(lines, startLine, endLine, []string{newLine})
		return writeIfChanged(path, lines, newLines)
	}

	// Append as a new child at the end of the compliance block. The
	// compliance key's column marks the sibling boundary; any line more
	// indented than that is a child of compliance.
	insertAt := walkPastChildrenOf(key.Column, key.Line, lines)
	newLines := insertLines(lines, insertAt, []string{newLine})
	return writeIfChanged(path, lines, newLines)
}

func replaceSingleLineCompliance(path string, lines []string, complianceKey *yaml.Node, ccms []string) (bool, error) {
	// Replace `compliance: {}` (or any single-line empty mapping value)
	// with a two-line block-form entry.
	keyIndent := complianceKey.Column - 1
	parentIndent := strings.Repeat(" ", keyIndent)
	childIndent := strings.Repeat(" ", keyIndent+2)
	startLine := complianceKey.Line - 1
	endLine := startLine + 1 // replace a single line
	block := []string{
		parentIndent + "compliance:",
		childIndent + ccmLine(ccms),
	}
	newLines := replaceLineRange(lines, startLine, endLine, block)
	return writeIfChanged(path, lines, newLines)
}

func insertNewCompliance(path string, lines []string, descKey, descVal *yaml.Node, ccms []string) (bool, error) {
	// Insert a new `compliance:` block after description's last line.
	// For block scalars (> or |), yaml.v3 marks the value's Line as the
	// header line, not the last continuation line. Walk forward past any
	// line more indented than the key — those are the block scalar's
	// continuation lines — to find the true end.
	insertAt := walkPastChildrenOf(descKey.Column, descVal.Line, lines)
	keyIndent := descKey.Column - 1
	parentIndent := strings.Repeat(" ", keyIndent)
	childIndent := strings.Repeat(" ", keyIndent+2)
	block := []string{
		parentIndent + "compliance:",
		childIndent + ccmLine(ccms),
	}
	newLines := insertLines(lines, insertAt, block)
	return writeIfChanged(path, lines, newLines)
}

// walkPastChildrenOf returns the 0-based line index just past the last
// continuation line for a parent whose key sits at keyColumn (1-based).
// Callers pass yaml.v3's Line value directly (1-based), which in this
// 0-based context is interpreted as "start scanning at the line after
// the parent key". It advances while each line is either blank or
// indented deeper than the parent's key column. Stops at the first
// line at keyColumn indent (a sibling key) or EOF.
func walkPastChildrenOf(keyColumn, startLine int, lines []string) int {
	i := startLine
	lastNonBlank := startLine - 1
	for i < len(lines) {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			i++
			continue
		}
		if leadingSpaces(line)+1 > keyColumn {
			lastNonBlank = i
			i++
			continue
		}
		break
	}
	return lastNonBlank + 1
}

// --- YAML node traversal helpers ---

func findChild(mapping *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i], mapping.Content[i+1]
		}
	}
	return nil, nil
}

// childIndentOfMapping returns the 0-based indent column of the first
// child key of a mapping node, or -1 if the mapping is empty.
func childIndentOfMapping(m *yaml.Node) int {
	if len(m.Content) == 0 {
		return -1
	}
	return m.Content[0].Column - 1
}

// endLineOfNode returns the 1-based line number just past the last
// textual line occupied by a YAML value. For scalars this is the node's
// Line; for collections we walk children to find the last child's end
// line and scan forward past any continuation lines at the same or
// greater indent.
func endLineOfNode(n *yaml.Node, lines []string) int {
	if n == nil {
		return 0
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return scalarEndLine(n, lines)
	case yaml.MappingNode, yaml.SequenceNode:
		if len(n.Content) == 0 {
			return n.Line + 1
		}
		// Walk children; for a mapping, last child is last even-indexed value.
		lastIdx := len(n.Content) - 1
		if n.Kind == yaml.MappingNode && lastIdx >= 1 {
			return endLineOfNode(n.Content[lastIdx], lines)
		}
		return endLineOfNode(n.Content[lastIdx], lines)
	}
	return n.Line + 1
}

// endLineOfMapping returns the 1-based line number just past the mapping.
func endLineOfMapping(m *yaml.Node, lines []string) int {
	return endLineOfNode(m, lines)
}

// scalarEndLine walks forward from the scalar's starting line to find
// the last textual line of the scalar's value. yaml.v3 reports Line as
// the line the value starts on. Multi-line block scalars (>, |) span
// continuation lines that are indented deeper than the key's column.
func scalarEndLine(n *yaml.Node, lines []string) int {
	startLine := n.Line // 1-based
	if startLine <= 0 || startLine > len(lines) {
		return startLine + 1
	}

	// For a plain-style or flow scalar, yaml.v3 usually sets Line to the
	// line containing the value. Multi-line block scalars are trickier:
	// yaml.v3 sets Line to the line of the `>` / `|` header, not the
	// first content line, but it reliably reports Column for the value
	// position. We scan forward past any continuation lines that:
	//   - are deeper-indented than the scalar's key column, or
	//   - are blank.
	// and stop at the first line at the scalar's column (a sibling key).
	col := n.Column // 1-based; for mapping values this is the value column
	end := startLine
	for i := startLine; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			end = i + 1
			continue
		}
		if leadingSpaces(line)+1 >= col {
			end = i + 1
			continue
		}
		break
	}
	return end
}

func leadingSpaces(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
			continue
		}
		break
	}
	return n
}

// --- line manipulation helpers ---

func splitLines(data []byte) []string {
	return strings.Split(string(data), "\n")
}

func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n"))
}

func replaceLineRange(lines []string, start, end int, with []string) []string {
	out := make([]string, 0, len(lines)-(end-start)+len(with))
	out = append(out, lines[:start]...)
	out = append(out, with...)
	out = append(out, lines[end:]...)
	return out
}

func insertLines(lines []string, at int, insert []string) []string {
	if at > len(lines) {
		at = len(lines)
	}
	out := make([]string, 0, len(lines)+len(insert))
	out = append(out, lines[:at]...)
	out = append(out, insert...)
	out = append(out, lines[at:]...)
	return out
}

func writeIfChanged(path string, before, after []string) (bool, error) {
	if equalLines(before, after) {
		return false, nil
	}
	return true, os.WriteFile(path, joinLines(after), 0o644)
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return bytes.Equal(joinLines(a), joinLines(b))
}

// --- report rendering ---

func renderReport(recs []controlRec) string {
	var sb strings.Builder
	total := len(recs)
	mapped := 0
	domainMapped := map[string]int{}
	domainTotal := map[string]int{}
	for _, r := range recs {
		svc, _, _ := strings.Cut(r.Dir, "/")
		domainTotal[svc]++
		if len(r.CCMs) > 0 {
			mapped++
			domainMapped[svc]++
		}
	}

	sb.WriteString("# CCM v4 Back-Fill Coverage Report\n\n")
	fmt.Fprintf(&sb, "- Total controls: %d\n", total)
	fmt.Fprintf(&sb, "- Mapped: %d (%.1f%%)\n", mapped, 100*float64(mapped)/float64(total))
	fmt.Fprintf(&sb, "- Unmapped (absent field): %d\n\n", total-mapped)

	sb.WriteString("## Coverage by service\n\n| Service | Mapped | Total | Coverage |\n|---|---|---|---|\n")
	keys := make([]string, 0, len(domainTotal))
	for k := range domainTotal {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		m := domainMapped[k]
		t := domainTotal[k]
		pct := 100 * float64(m) / float64(t)
		fmt.Fprintf(&sb, "| %s | %d | %d | %.0f%% |\n", k, m, t, pct)
	}

	sb.WriteString("\n## Ambiguous controls (left absent)\n\n")
	unmapped := []controlRec{}
	for _, r := range recs {
		if len(r.CCMs) == 0 {
			unmapped = append(unmapped, r)
		}
	}
	slices.SortFunc(unmapped, func(a, b controlRec) int {
		return cmp.Compare(a.Rel, b.Rel)
	})
	if len(unmapped) == 0 {
		sb.WriteString("(none)\n")
	} else {
		for _, r := range unmapped {
			fmt.Fprintf(&sb, "- `%s` (%s)\n", r.ID, r.Rel)
		}
	}
	return sb.String()
}
