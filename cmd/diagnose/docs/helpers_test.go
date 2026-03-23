package docs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// getTestRootCmd builds a minimal root command with docs subcommands attached.
func getTestRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("output", "text", "Output format")
	root.PersistentFlags().Bool("quiet", false, "Suppress output")
	root.PersistentFlags().CountP("verbose", "v", "Increase verbosity")
	root.PersistentFlags().Bool("force", false, "Allow overwrite")
	root.PersistentFlags().Bool("sanitize", false, "Sanitize identifiers")
	root.PersistentFlags().String("path-mode", "base", "Path rendering mode")
	root.PersistentFlags().String("log-file", "", "Log file path")

	docsCmd := &cobra.Command{Use: "docs", Short: "Documentation commands"}
	docsCmd.AddCommand(NewDocsSearchCmd())
	docsCmd.AddCommand(NewDocsOpenCmd())
	root.AddCommand(docsCmd)

	return root
}

// execDocsSearch sets up a root command, runs "docs search" with the given
// args, and returns the combined stdout+stderr output. Fails the test on error.
func execDocsSearch(t *testing.T, args ...string) string {
	t.Helper()
	root := getTestRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"docs", "search"}, args...))
	if err := root.Execute(); err != nil {
		t.Fatalf("docs search command failed: %v\nstderr: %s", err, stderr.String())
	}
	return stdout.String()
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
}
