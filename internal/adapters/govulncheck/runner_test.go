package govulncheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_CommandNotFound(t *testing.T) {
	// If govulncheck is not installed, Run should return an error.
	if _, err := exec.LookPath("govulncheck"); err != nil {
		_, err := Run(context.Background(), t.TempDir())
		if err == nil {
			t.Fatal("expected error when govulncheck is not available")
		}
		return
	}

	// govulncheck is available but running in a non-Go directory should fail.
	_, err := Run(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected error when running in a non-Go directory")
	}
}

// TestRun_RejectsEmptyOutputUnderCleanExit pins the subprocess-
// boundary contract (bug-1 class): a clean exit (0) from govulncheck
// still must carry the JSON report on stdout. If the binary exits 0
// with empty output, Run must surface an error rather than handing
// the caller an empty byte slice that later parses to "no findings"
// and gets recorded as a clean scan.
func TestRun_RejectsEmptyOutputUnderCleanExit(t *testing.T) {
	// Fake govulncheck: exit 0, emit nothing.
	dir := t.TempDir()
	fake := filepath.Join(dir, "govulncheck")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake govulncheck: %v", err)
	}
	t.Setenv("PATH", dir)

	_, err := Run(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected error when govulncheck exits 0 with empty stdout, got nil")
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Fatalf("error should explain the empty-output contract violation, got: %v", err)
	}
}

func TestRun_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := Run(ctx, t.TempDir())
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}
