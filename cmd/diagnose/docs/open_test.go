//go:build stavedev

package docs

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsOpenCommand_TextOutput(t *testing.T) {
	temp := t.TempDir()
	docPath := filepath.Join(temp, "docs", "user-docs.md")
	writeTestFile(t, docPath, "# User Docs\nUse snapshot upcoming to plan actions in order.\n")

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"docs", "open", "snapshot upcoming",
		"--docs-root", temp,
		"--path", "docs",
		"--format", "text",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("docs open command failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `Topic: "snapshot upcoming"`) {
		t.Fatalf("expected topic header, got: %s", out)
	}
	if !strings.Contains(out, "Path: "+docPath) {
		t.Fatalf("expected exact path, got: %s", out)
	}
	if !strings.Contains(out, "Summary: Use snapshot upcoming to plan actions in order.") {
		t.Fatalf("expected summary, got: %s", out)
	}
}

func TestDocsOpenCommand_JSONOutput(t *testing.T) {
	temp := t.TempDir()
	docPath := filepath.Join(temp, "README.md")
	writeTestFile(t, docPath, "stave ci gate enforces CI failure policy.\n")

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"docs", "open", "ci gate",
		"--docs-root", temp,
		"--path", "README.md",
		"--format", "json",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("docs open command failed: %v", err)
	}

	var out OpenResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode json output: %v\noutput=%s", err, buf.String())
	}
	if out.Path != docPath {
		t.Fatalf("unexpected path: %q", out.Path)
	}
	if out.Summary == "" {
		t.Fatal("expected summary")
	}
}

func TestDocsOpenCommand_NoMatches(t *testing.T) {
	temp := t.TempDir()
	writeTestFile(t, filepath.Join(temp, "README.md"), "nothing relevant here\n")

	root := getTestRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{
		"docs", "open", "snapshot upcoming",
		"--docs-root", temp,
		"--path", "README.md",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected no-match error")
	}
	if !strings.Contains(err.Error(), "stave docs search") {
		t.Fatalf("expected search guidance in error, got: %v", err)
	}
}
