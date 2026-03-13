package extractor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runScaffold(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	baseDir := filepath.Join(opts.Dir, opts.Name)
	if err := fsutil.SafeMkdirAll(baseDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}); err != nil {
		return fmt.Errorf("create directory %s: %w", baseDir, err)
	}

	rt.Quiet = cmdutil.QuietEnabled(cmd)
	done := rt.BeginProgress("scaffold extractor")
	defer done()

	files := map[string]string{
		"README.md":         extractorReadme(opts.Name),
		"extractor.yaml":    extractorMetadata(opts.Name),
		"transform.go":      extractorTransformGo(opts.Name),
		"transform_test.go": extractorTransformTestGo(opts.Name),
		"Makefile":          extractorMakefile(opts.Name),
	}

	var created []string
	var skipped []string
	for rel, content := range files {
		full := filepath.Join(baseDir, rel)
		wrote, err := writeScaffoldFile(full, []byte(content), cmdutil.ForceEnabled(cmd))
		if err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
		if wrote {
			created = append(created, rel)
			continue
		}
		skipped = append(skipped, rel)
	}

	if rt.Quiet {
		return nil
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Scaffolded extractor %q at %s\n", opts.Name, baseDir)
	for _, rel := range created {
		_, _ = fmt.Fprintf(out, "  - %s\n", rel)
	}
	if len(skipped) > 0 {
		_, _ = fmt.Fprintln(out, "\nSkipped existing files (use --force to overwrite):")
		for _, rel := range skipped {
			_, _ = fmt.Fprintf(out, "  - %s\n", rel)
		}
	}
	return nil
}

// writeScaffoldFile writes a file only if it doesn't already exist (or force is true).
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

// normalizeTemplate trims a leading newline and ensures a trailing newline.
func normalizeTemplate(s string) string {
	s = strings.TrimLeft(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}
