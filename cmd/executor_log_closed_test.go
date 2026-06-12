package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestExecute_LoggerRemainsOpenForFinalize(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "stave.log")

	// Pre-create the directory to make sure it's valid.
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	a := &App{}
	a.Root = &cobra.Command{
		Use: "test",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}

	a.Root.PersistentPreRunE = a.bootstrap
	a.Root.PersistentPostRun = a.postRun

	a.Flags.Verbosity = 2 // Enable DEBUG logs
	a.Flags.LogFile = logPath

	// Mock ExitFunc to avoid os.Exit.
	a.ExitFunc = func(code int) {
		if code != ui.ExitSuccess {
			t.Errorf("expected exit success, got code %d", code)
		}
	}

	ctx := context.Background()
	a.Root.SetContext(ctx)

	a.execute()

	// Now read the log file and verify it contains the finalization debug log.
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	logContent := string(logBytes)
	t.Logf("Log content:\n%s", logContent)

	if !strings.Contains(logContent, "session persistence skipped") {
		t.Error("expected log file to contain finalization log 'session persistence skipped', but it did not (log file was likely closed prematurely)")
	}
}
