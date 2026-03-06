package bugreport

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunInspect_DumpsEntries(t *testing.T) {
	zipPath := createTestBundle(t, []testEntry{
		{"manifest.json", `{"bundle_version":"bug-report.v0.1"}` + "\n"},
		{"doctor.json", `{"ready":true}` + "\n"},
	})

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runInspect(cmd, []string{zipPath}); err != nil {
		t.Fatalf("inspect failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "=== doctor.json ===") {
		t.Fatalf("missing doctor.json header in output:\n%s", out)
	}
	if !strings.Contains(out, "=== manifest.json ===") {
		t.Fatalf("missing manifest.json header in output:\n%s", out)
	}
	// Entries should be sorted: doctor.json before manifest.json.
	doctorIdx := strings.Index(out, "=== doctor.json ===")
	manifestIdx := strings.Index(out, "=== manifest.json ===")
	if doctorIdx > manifestIdx {
		t.Fatalf("expected doctor.json before manifest.json in sorted output:\n%s", out)
	}
	if !strings.Contains(out, `"ready":true`) {
		t.Fatalf("missing doctor.json content in output:\n%s", out)
	}
}

func TestRunInspect_SkipsLargeFiles(t *testing.T) {
	zipPath := createTestBundle(t, []testEntry{
		{"small.txt", "hello\n"},
		{"big.txt", strings.Repeat("x", 200)},
	})

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	// Use a limit of 100 bytes so big.txt (200 bytes) gets skipped.
	if err := dumpBundle(cmd, zipPath, int64(100)); err != nil {
		t.Fatalf("inspect failed: %v", err)
	}

	if !strings.Contains(stdout.String(), "=== small.txt ===") {
		t.Fatalf("missing small.txt in output:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "=== big.txt ===") {
		t.Fatalf("big.txt should have been skipped:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "skipping big.txt") {
		t.Fatalf("expected skip warning on stderr, got:\n%s", stderr.String())
	}
}

type testEntry struct {
	name, body string
}

func createTestBundle(t *testing.T, entries []testEntry) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "test-bundle.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, wErr := zw.Create(e.name)
		if wErr != nil {
			t.Fatal(wErr)
		}
		if _, wErr = w.Write([]byte(e.body)); wErr != nil {
			t.Fatal(wErr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return zipPath
}
