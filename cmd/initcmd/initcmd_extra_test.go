package initcmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// --- normalizeTemplate ---

func TestNormalizeTemplate_TrimsLeadingNewlines(t *testing.T) {
	got := normalizeTemplate("\n\n\nhello")
	if strings.HasPrefix(got, "\n") {
		t.Fatalf("expected leading newlines trimmed, got: %q", got)
	}
}

func TestNormalizeTemplate_AddsTrailingNewline(t *testing.T) {
	got := normalizeTemplate("hello")
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected trailing newline, got: %q", got)
	}
}

func TestNormalizeTemplate_PreservesExistingTrailing(t *testing.T) {
	got := normalizeTemplate("hello\n")
	if strings.HasSuffix(got, "\n\n") {
		t.Fatalf("should not double trailing newline, got: %q", got)
	}
}

func TestNormalizeTemplate_Empty(t *testing.T) {
	got := normalizeTemplate("")
	if got != "" {
		t.Fatalf("expected empty string, got: %q", got)
	}
}

// --- controlIDFromName ---

func TestControlIDFromName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"S3 Public Read", "CTL.S3.PUBLIC_READ.001"},
		{"public", "CTL.PUBLIC.SAMPLE.001"},
		{"", "CTL.GENERATED.SAMPLE.001"},
		{"  ", "CTL.GENERATED.SAMPLE.001"},
		{"a-b-c", "CTL.A.B_C.001"},
	}
	for _, tt := range tests {
		got := controlIDFromName(tt.name)
		if got != tt.want {
			t.Errorf("controlIDFromName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// --- sanitizeSlug ---

func TestSanitizeSlug(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"My Bucket", "my-bucket"},
		{"  hello  ", "hello"},
		{"a/b/c", "a-b-c"},
		{"A!B@C#D", "a-b-c-d"},
		{"", "snapshot"},
		{"  ", "snapshot"},
		{"---", "snapshot"},
		{"test-bucket", "test-bucket"},
		{"UPPER case Mix", "upper-case-mix"},
	}
	for _, tt := range tests {
		got := sanitizeSlug(tt.name)
		if got != tt.want {
			t.Errorf("sanitizeSlug(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// --- snapshotFilenameTemplate ---

func TestSnapshotFilenameTemplate(t *testing.T) {
	tests := []struct {
		cadence string
		want    string
	}{
		{cadenceHourly, "YYYY-MM-DDTHH0000Z.json"},
		{cadenceDaily, "YYYY-MM-DDT000000Z.json"},
		{"", "YYYY-MM-DDT000000Z.json"},
	}
	for _, tt := range tests {
		got := snapshotFilenameTemplate(tt.cadence)
		if got != tt.want {
			t.Errorf("snapshotFilenameTemplate(%q) = %q, want %q", tt.cadence, got, tt.want)
		}
	}
}

// --- snapshotFilenameExample ---

func TestSnapshotFilenameExample(t *testing.T) {
	tests := []struct {
		cadence string
		want    string
	}{
		{cadenceHourly, "2026-01-18T140000Z.json"},
		{cadenceDaily, "2026-01-18T000000Z.json"},
		{"", "2026-01-18T000000Z.json"},
	}
	for _, tt := range tests {
		got := snapshotFilenameExample(tt.cadence)
		if got != tt.want {
			t.Errorf("snapshotFilenameExample(%q) = %q, want %q", tt.cadence, got, tt.want)
		}
	}
}

// --- shellDateFormat ---

func TestShellDateFormat(t *testing.T) {
	if got := shellDateFormat(cadenceHourly); !strings.Contains(got, "%H") {
		t.Fatalf("hourly format should contain %%H, got: %q", got)
	}
	if got := shellDateFormat(cadenceDaily); strings.Contains(got, "%H") {
		t.Fatalf("daily format should not contain %%H, got: %q", got)
	}
}

// --- scheduleBlock ---

func TestScheduleBlock(t *testing.T) {
	hourly := scheduleBlock(cadenceHourly)
	if !strings.Contains(hourly, "0 * * * *") {
		t.Fatalf("expected hourly cron, got: %q", hourly)
	}
	daily := scheduleBlock(cadenceDaily)
	if !strings.Contains(daily, "0 2 * * *") {
		t.Fatalf("expected daily cron, got: %q", daily)
	}
}

// --- Version ---

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Fatal("Version() should not be empty")
	}
}

// --- printScaffoldSummary ---

func TestPrintScaffoldSummary_Quiet(t *testing.T) {
	// Quiet mode: caller passes io.Discard as writer.
	printScaffoldSummary(io.Discard, io.Discard, scaffoldSummaryRequest{
		BaseDir: "/tmp/test",
		Dirs:    []string{"controls"},
		Created: []string{"stave.yaml"},
	})
}

func TestPrintScaffoldSummary_DryRun(t *testing.T) {
	var buf bytes.Buffer
	printScaffoldSummary(&buf, io.Discard, scaffoldSummaryRequest{
		BaseDir: "/tmp/test",
		Dirs:    []string{"controls", "observations"},
		Created: []string{"stave.yaml", "README.md"},
		DryRun:  true,
	})
	out := buf.String()
	if !strings.Contains(out, "Dry run") {
		t.Fatalf("expected dry run header, got: %s", out)
	}
	if !strings.Contains(out, "No files were written") {
		t.Fatalf("expected dry run footer, got: %s", out)
	}
}

func TestPrintScaffoldSummary_Normal(t *testing.T) {
	var buf bytes.Buffer
	printScaffoldSummary(&buf, io.Discard, scaffoldSummaryRequest{
		BaseDir: "/tmp/test",
		Dirs:    []string{"controls"},
		Created: []string{"stave.yaml"},
	})
	out := buf.String()
	if !strings.Contains(out, "Initialized empty Stave project") {
		t.Fatalf("expected init message, got: %s", out)
	}
	if !strings.Contains(out, "Created structure") {
		t.Fatalf("expected Created structure, got: %s", out)
	}
}

func TestPrintScaffoldSummary_WithSkipped(t *testing.T) {
	var buf bytes.Buffer
	printScaffoldSummary(&buf, io.Discard, scaffoldSummaryRequest{
		BaseDir: "/tmp/test",
		Dirs:    []string{"controls"},
		Created: []string{"stave.yaml"},
		Skipped: []string{"README.md"},
	})
	out := buf.String()
	if !strings.Contains(out, "Skipped existing files") {
		t.Fatalf("expected skipped files section, got: %s", out)
	}
	if !strings.Contains(out, "README.md") {
		t.Fatalf("expected README.md in skipped, got: %s", out)
	}
}

// --- printCreatedTree ---

func TestPrintCreatedTree(t *testing.T) {
	var buf bytes.Buffer
	dirs := []string{"controls", "observations"}
	files := []string{"stave.yaml", "README.md"}
	printCreatedTree(&buf, dirs, files)
	out := buf.String()
	if !strings.Contains(out, "controls") {
		t.Fatalf("expected controls in tree, got: %s", out)
	}
	if !strings.Contains(out, "observations") {
		t.Fatalf("expected observations in tree, got: %s", out)
	}
}

// --- addTreePath ---

func TestAddTreePath_EmptyPath(t *testing.T) {
	root := &summaryTreeNode{children: make(map[string]*summaryTreeNode)}
	addTreePath(root, "", true)
	if len(root.children) != 0 {
		t.Fatal("expected no children for empty path")
	}
}

func TestAddTreePath_NestedDir(t *testing.T) {
	root := &summaryTreeNode{children: make(map[string]*summaryTreeNode)}
	addTreePath(root, "a/b/c", true)
	if _, ok := root.children["a"]; !ok {
		t.Fatal("expected 'a' child")
	}
	if !root.children["a"].isDir {
		t.Fatal("expected 'a' to be a dir")
	}
}

// --- GenerateRunner ---

func TestGenerateRunner_RunControl_EmptyName(t *testing.T) {
	r := &GenerateRunner{Out: io.Discard}
	err := r.RunControl(GenerateRequest{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateRunner_RunObservation_EmptyName(t *testing.T) {
	r := &GenerateRunner{Out: io.Discard}
	err := r.RunObservation(GenerateRequest{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestGenerateRunner_RunControl_WriteToTempDir(t *testing.T) {
	tmp := t.TempDir()
	var buf bytes.Buffer
	r := &GenerateRunner{Out: &buf, Force: true}
	err := r.RunControl(GenerateRequest{Name: "test", Out: tmp + "/test.yaml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Generated") {
		t.Fatalf("expected 'Generated' message, got: %s", buf.String())
	}
}

func TestGenerateRunner_RunObservation_WriteToTempDir(t *testing.T) {
	tmp := t.TempDir()
	var buf bytes.Buffer
	r := &GenerateRunner{Out: &buf, Force: true}
	err := r.RunObservation(GenerateRequest{Name: "test", Out: tmp + "/test.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Generated") {
		t.Fatalf("expected 'Generated' message, got: %s", buf.String())
	}
}

func TestGenerateRunner_RunControl_Quiet(t *testing.T) {
	tmp := t.TempDir()
	var buf bytes.Buffer
	r := &GenerateRunner{Out: &buf, Force: true, Quiet: true}
	err := r.RunControl(GenerateRequest{Name: "test", Out: tmp + "/test.yaml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %s", buf.String())
	}
}

func TestGenerateRunner_RunControl_FileExists(t *testing.T) {
	tmp := t.TempDir()
	// Create the file first
	outPath := tmp + "/test.yaml"
	r := &GenerateRunner{Out: io.Discard, Force: true}
	if err := r.RunControl(GenerateRequest{Name: "test", Out: outPath}); err != nil {
		t.Fatal(err)
	}
	// Try again without force
	r.Force = false
	err := r.RunControl(GenerateRequest{Name: "test", Out: outPath})
	if err == nil {
		t.Fatal("expected error for existing file without --force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}
