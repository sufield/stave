//go:build integration

package docsverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const commandTimeout = 30 * time.Second

var extractLangs = []string{"bash", "shell", "sh"}

func TestDocumentationCommands(t *testing.T) {
	repoRoot := findRepoRoot(t)
	bin := buildBinary(t, repoRoot)

	docsDir := filepath.Join(repoRoot, "docs")
	var mdFiles []string
	err := filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".md") {
			mdFiles = append(mdFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs dir: %v", err)
	}

	if len(mdFiles) == 0 {
		t.Skip("no .md files found in docs/")
	}

	var total, skipped, tested int
	for _, file := range mdFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("read %s: %v", file, err)
			continue
		}

		commands, err := ExtractCommands(content, file, extractLangs)
		if err != nil {
			t.Errorf("extract %s: %v", file, err)
			continue
		}

		relFile, _ := filepath.Rel(repoRoot, file)
		for _, cmd := range commands {
			total++
			subcommand := "unknown"
			if fields := strings.Fields(cmd.Command); len(fields) > 1 {
				subcommand = fields[1]
			}
			testName := filepath.Base(cmd.File) + ":" + subcommand

			t.Run(testName, func(t *testing.T) {
				if cmd.Skip {
					skipped++
					t.Skipf("doctest:skip (%s:%d): %s", relFile, cmd.Line, cmd.SkipReason)
				}
				tested++

				args := strings.Fields(cmd.Command)
				ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
				defer cancel()

				run := exec.CommandContext(ctx, bin, args[1:]...)
				run.Dir = repoRoot

				output, err := run.CombinedOutput()
				exitCode := 0
				if err != nil {
					if ctx.Err() == context.DeadlineExceeded {
						t.Fatalf("%s:%d timed out after %s\nCommand: %s",
							relFile, cmd.Line, commandTimeout, cmd.Command)
					}
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					} else {
						t.Fatalf("%s:%d failed to run: %v", relFile, cmd.Line, err)
					}
				}

				if cmd.ExpectError {
					if exitCode == 0 {
						t.Errorf("%s:%d expected non-zero exit but got 0\nCommand: %s",
							relFile, cmd.Line, cmd.Command)
					}
					return
				}

				// Exit 3 = violations found = success for apply
				if exitCode != 0 && exitCode != 3 {
					t.Errorf("%s:%d exit %d\nCommand: %s\nOutput:\n%s",
						relFile, cmd.Line, exitCode, cmd.Command, truncate(output, 500))
				}
			})
		}
	}

	t.Logf("docs: %d commands found, %d tested, %d skipped", total, tested, skipped)
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "\n... (truncated)"
}

func buildBinary(t *testing.T, repoRoot string) string {
	t.Helper()
	cmd := exec.Command("make", "build")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make build: %v\n%s", err, out)
	}
	bin := filepath.Join(repoRoot, "stave")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("binary not found at %s: %v", bin, err)
	}
	return bin
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}
