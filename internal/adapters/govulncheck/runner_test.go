package govulncheck

import (
	"context"
	"os/exec"
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

func TestRun_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := Run(ctx, t.TempDir())
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}
