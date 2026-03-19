//go:build stavedev

package docs

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsSearchCommand_TextOutput(t *testing.T) {
	temp := t.TempDir()
	writeTestFile(t, filepath.Join(temp, "README.md"), "# Stave\nUse stave snapshot upcoming to plan next actions.\n")
	writeTestFile(t, filepath.Join(temp, "docs", "user-docs.md"), "Run `stave snapshot upcoming` and `stave ci gate`.\n")

	out := execDocsSearch(t,
		"snapshot upcoming",
		"--docs-root", temp,
		"--path", "README.md",
		"--path", "docs",
		"--format", "text",
		"--show", "5",
	)
	if !strings.Contains(out, `Query: "snapshot upcoming"`) {
		t.Fatalf("expected query header, got: %s", out)
	}
	if !strings.Contains(out, "README.md:2") {
		t.Fatalf("expected match location in output, got: %s", out)
	}
	if !strings.Contains(out, "snapshot upcoming") {
		t.Fatalf("expected matched snippet in output, got: %s", out)
	}
}

func TestDocsSearchCommand_JSONOutput(t *testing.T) {
	temp := t.TempDir()
	writeTestFile(t, filepath.Join(temp, "README.md"), "stave ci gate enforces policy.\n")

	raw := execDocsSearch(t,
		"ci gate",
		"--docs-root", temp,
		"--path", "README.md",
		"--format", "json",
	)

	var out SearchResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("failed to decode json output: %v\noutput=%s", err, raw)
	}
	if out.Query != "ci gate" {
		t.Fatalf("unexpected query: %q", out.Query)
	}
	if out.Total < 1 || out.Returned < 1 {
		t.Fatalf("expected at least one hit, got total=%d returned=%d", out.Total, out.Returned)
	}
}

func TestDocsSearchCommand_NoMatches(t *testing.T) {
	temp := t.TempDir()
	writeTestFile(t, filepath.Join(temp, "README.md"), "nothing relevant here\n")

	out := execDocsSearch(t,
		"snapshot upcoming",
		"--docs-root", temp,
		"--path", "README.md",
		"--format", "text",
	)
	if !strings.Contains(out, "No matches found.") {
		t.Fatalf("expected no matches message, got: %s", out)
	}
}
