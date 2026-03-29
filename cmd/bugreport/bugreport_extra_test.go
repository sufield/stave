package bugreport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTailBytesByLine_Normal(t *testing.T) {
	data := []byte("line1\nline2\nline3\nline4\nline5\n")
	got := TailBytesByLine(data, 2)
	want := "line4\nline5"
	if string(got) != want {
		t.Fatalf("TailBytesByLine(2) = %q, want %q", string(got), want)
	}
}

func TestTailBytesByLine_MoreLinesThanAvailable(t *testing.T) {
	data := []byte("line1\nline2\n")
	got := TailBytesByLine(data, 10)
	if string(got) != string(data) {
		t.Fatalf("TailBytesByLine(10) = %q, want %q", string(got), string(data))
	}
}

func TestTailBytesByLine_Zero(t *testing.T) {
	data := []byte("line1\nline2\n")
	got := TailBytesByLine(data, 0)
	if got != nil {
		t.Fatalf("TailBytesByLine(0) = %v, want nil", got)
	}
}

func TestTailBytesByLine_Empty(t *testing.T) {
	got := TailBytesByLine(nil, 5)
	if got != nil {
		t.Fatalf("TailBytesByLine(nil) = %v, want nil", got)
	}
}

func TestTailBytesByLine_SingleLine(t *testing.T) {
	data := []byte("only line\n")
	got := TailBytesByLine(data, 1)
	// Single line with trailing newline: fewer lines than maxLines => return original data.
	if string(got) != string(data) {
		t.Fatalf("TailBytesByLine(1) = %q, want %q", string(got), string(data))
	}
}

func TestSanitizeArgs_Nil(t *testing.T) {
	got := SanitizeArgs(nil)
	if got != nil {
		t.Fatalf("SanitizeArgs(nil) = %v, want nil", got)
	}
}

func TestSanitizeArgs_Empty(t *testing.T) {
	got := SanitizeArgs([]string{})
	if got != nil {
		t.Fatalf("SanitizeArgs(empty) = %v, want nil", got)
	}
}

func TestSanitizeArgs_Normal(t *testing.T) {
	args := []string{"stave", "apply", "--controls", "ctl"}
	got := SanitizeArgs(args)
	if len(got) != 4 {
		t.Fatalf("SanitizeArgs len = %d, want 4", len(got))
	}
}

func TestFilterEnv_IncludesRelevant(t *testing.T) {
	environ := []string{
		"STAVE_DEBUG=1",
		"AWS_REGION=us-east-1",
		"HOME=/home/user",
		"PATH=/usr/bin",
	}
	entries := FilterEnv(environ)
	keys := make(map[string]string, len(entries))
	for _, e := range entries {
		keys[e.Key] = e.Value
	}
	if _, ok := keys["STAVE_DEBUG"]; !ok {
		t.Fatal("expected STAVE_DEBUG")
	}
	if _, ok := keys["AWS_REGION"]; !ok {
		t.Fatal("expected AWS_REGION")
	}
	if _, ok := keys["PATH"]; !ok {
		t.Fatal("expected PATH")
	}
	if _, ok := keys["HOME"]; ok {
		t.Fatal("HOME should not be collected")
	}
}

func TestFilterEnv_SkipsEmptyValues(t *testing.T) {
	environ := []string{
		"STAVE_DEBUG=",
		"AWS_REGION=   ",
	}
	entries := FilterEnv(environ)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for empty values, got %d", len(entries))
	}
}

func TestFilterEnv_SanitizesSensitive(t *testing.T) {
	environ := []string{
		"AWS_SECRET_ACCESS_KEY=secret123",
		"STAVE_TOKEN=mytoken",
	}
	entries := FilterEnv(environ)
	for _, e := range entries {
		if e.Value != "[SANITIZED]" {
			t.Fatalf("expected [SANITIZED] for %s, got %q", e.Key, e.Value)
		}
	}
}

func TestFilterEnv_Sorted(t *testing.T) {
	environ := []string{
		"STAVE_Z=1",
		"STAVE_A=2",
		"STAVE_M=3",
	}
	entries := FilterEnv(environ)
	for i := 1; i < len(entries); i++ {
		if entries[i].Key < entries[i-1].Key {
			t.Fatalf("entries not sorted: %s before %s", entries[i-1].Key, entries[i].Key)
		}
	}
}

func TestCollectBuildInfo_Runtime(t *testing.T) {
	info := CollectBuildInfo()
	if info.Runtime == nil {
		t.Fatal("expected non-nil Runtime")
	}
	if info.Runtime["goos"] == "" {
		t.Fatal("expected non-empty goos")
	}
	if info.Runtime["goarch"] == "" {
		t.Fatal("expected non-empty goarch")
	}
}

func TestFindLogPath_Found(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "test.log")
	if err := os.WriteFile(logFile, []byte("log data"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := FindLogPath("", logFile, "/nonexistent")
	if !ok {
		t.Fatal("expected to find log file")
	}
	if got != logFile {
		t.Fatalf("got %q, want %q", got, logFile)
	}
}

func TestFindLogPath_NotFound(t *testing.T) {
	_, ok := FindLogPath("/nonexistent/a.log", "/nonexistent/b.log")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestFindLogPath_EmptyCandidates(t *testing.T) {
	_, ok := FindLogPath("", "  ")
	if ok {
		t.Fatal("expected not found for empty candidates")
	}
}

func TestFindLogPath_Directory(t *testing.T) {
	tmp := t.TempDir()
	_, ok := FindLogPath(tmp) // dir, not file
	if ok {
		t.Fatal("expected not found for directory path")
	}
}

func TestResolveDefaultOutPath_Override(t *testing.T) {
	got := ResolveDefaultOutPath("/cwd", "/custom/path.zip", time.Time{})
	if got != "/custom/path.zip" {
		t.Fatalf("got %q, want /custom/path.zip", got)
	}
}

func TestResolveDefaultOutPath_Default(t *testing.T) {
	now := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	got := ResolveDefaultOutPath("/cwd", "", now)
	if !strings.HasPrefix(got, "/cwd/stave-diag-") {
		t.Fatalf("expected path under /cwd, got %q", got)
	}
	if !strings.Contains(got, "20260315") {
		t.Fatalf("expected date in path, got %q", got)
	}
	if !strings.HasSuffix(got, ".zip") {
		t.Fatalf("expected .zip extension, got %q", got)
	}
}

func TestResolveDefaultOutPath_WhitespaceOverride(t *testing.T) {
	got := ResolveDefaultOutPath("/cwd", "  ", time.Time{})
	// Whitespace-only should be treated as empty
	if strings.TrimSpace(got) == "" {
		t.Fatal("expected non-empty path")
	}
}

func TestWriteSummary(t *testing.T) {
	var buf bytes.Buffer
	WriteSummary(&buf, "/tmp/diag.zip")
	out := buf.String()
	if !strings.Contains(out, "/tmp/diag.zip") {
		t.Fatalf("expected path in summary, got: %s", out)
	}
	if !strings.Contains(out, "bug-report inspect") {
		t.Fatalf("expected inspect command hint, got: %s", out)
	}
}

func TestSanitizeLogTail_WithCredentials(t *testing.T) {
	data := []byte("line1\naccess_key: AKIAABCDEFGHIJKLMNOP\nhttps://user:pass@host.com\nline4\n")
	got := SanitizeLogTail(data, 10)
	if strings.Contains(string(got), "AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("AKIA key should be sanitized")
	}
	if strings.Contains(string(got), "user:pass@") {
		t.Fatal("URL credentials should be sanitized")
	}
}

func TestSanitizeLogTail_EmptyData(t *testing.T) {
	got := SanitizeLogTail(nil, 10)
	if len(got) != 0 {
		t.Fatalf("expected empty for nil data, got %d bytes", len(got))
	}
}

func TestSanitizeLogTail_ZeroLines(t *testing.T) {
	got := SanitizeLogTail([]byte("data"), 0)
	if got != nil {
		t.Fatalf("expected nil for 0 lines, got %v", got)
	}
}
