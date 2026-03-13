package extractor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// scaffoldResult tracks what happened during the operation for the UI.
type scaffoldResult struct {
	baseDir string
	created []string
	skipped []string
}

func runScaffold(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	// 1. Extract environment/flag state from cmd once
	force := cmdutil.ForceEnabled(cmd)
	allowSymlinks := cmdutil.AllowSymlinkOutEnabled(cmd)
	rt.Quiet = cmdutil.QuietEnabled(cmd)

	// 2. Setup directory
	baseDir := filepath.Join(opts.Dir, opts.Name)
	err := fsutil.SafeMkdirAll(baseDir, fsutil.WriteOptions{
		Perm:         0o755,
		AllowSymlink: allowSymlinks,
	})
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", baseDir, err)
	}

	// 3. Define scaffold files (Slice ensures deterministic order)
	files := []struct {
		name    string
		content string
	}{
		{"README.md", extractorReadme(opts.Name)},
		{"extractor.yaml", extractorMetadata(opts.Name)},
		{"transform.go", extractorTransformGo(opts.Name)},
		{"transform_test.go", extractorTransformTestGo(opts.Name)},
		{"Makefile", extractorMakefile(opts.Name)},
	}

	// 4. Perform operations
	done := rt.BeginProgress("scaffold extractor")
	res := &scaffoldResult{baseDir: baseDir}

	for _, f := range files {
		path := filepath.Join(baseDir, f.name)

		wrote, err := writeScaffoldFile(path, []byte(f.content), force)
		if err != nil {
			done()
			return fmt.Errorf("could not write %s: %w", f.name, err)
		}

		if wrote {
			res.created = append(res.created, f.name)
		} else {
			res.skipped = append(res.skipped, f.name)
		}
	}
	done()

	// 5. UI Reporting
	if !rt.Quiet {
		printReport(cmd.OutOrStdout(), opts.Name, res)
	}

	return nil
}

// writeScaffoldFile returns (true, nil) if written, (false, nil) if skipped, or an error.
func writeScaffoldFile(path string, data []byte, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}

	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = force

	if err := fsutil.SafeWriteFile(path, data, opts); err != nil {
		return false, err
	}
	return true, nil
}

func printReport(out io.Writer, name string, res *scaffoldResult) {
	fmt.Fprintf(out, "Scaffolded extractor %q at %s\n", name, res.baseDir)
	for _, rel := range res.created {
		fmt.Fprintf(out, "  - %s\n", rel)
	}

	if len(res.skipped) > 0 {
		fmt.Fprintln(out, "\nSkipped existing files (use --force to overwrite):")
		for _, rel := range res.skipped {
			fmt.Fprintf(out, "  - %s\n", rel)
		}
	}
}

// normalizeTemplate ensures consistent formatting for generated file strings.
func normalizeTemplate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return s + "\n"
}
