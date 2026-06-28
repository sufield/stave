package transform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	awstransform "github.com/sufield/stave/internal/adapters/aws/transform"
	"github.com/sufield/stave/internal/cli/ui"
)

func run(cmd *cobra.Command, o *options) error {
	r, err := NewRenderer(o.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	if o.coverage {
		if err = r.RenderCoverage(cmd.OutOrStdout(), awstransform.SupportedInputs()); err != nil {
			return fmt.Errorf("render coverage: %w", err)
		}
		return nil
	}

	if o.scaffold != "" {
		return scaffold(cmd, o.scaffold)
	}

	if o.lint {
		issues, lerr := awstransform.LintFilters()
		if lerr != nil {
			return fmt.Errorf("lint filters: %w", lerr)
		}
		if err = r.RenderLint(cmd.OutOrStdout(), issues); err != nil {
			return fmt.Errorf("render lint: %w", err)
		}
		for _, is := range issues {
			if is.Fatal {
				return &ui.UserError{Err: fmt.Errorf("filter lint found %d fatal issue(s)", countFatal(issues))}
			}
		}
		return nil
	}

	files, err := readRawDir(o.inDir)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if len(files) == 0 {
		return &ui.UserError{Err: fmt.Errorf("no .json files found in %s", o.inDir)}
	}

	capturedAt := o.capturedAt()
	out, stats, err := awstransform.TransformFiles(files, awstransform.Options{
		Account:    o.account,
		CapturedAt: capturedAt,
	})
	if err != nil {
		return fmt.Errorf("transform: %w", err)
	}

	res := result{
		Files:     stats.Files,
		Assets:    stats.Assets,
		Skipped:   stats.Skipped,
		Validated: true,
	}

	// --out -: write the observation to stdout and the summary to stderr so the
	// two streams don't mix. Otherwise write one file into the output directory.
	summaryOut := cmd.OutOrStdout()
	if o.outDir == "-" {
		if _, err = cmd.OutOrStdout().Write(out); err != nil {
			return fmt.Errorf("write observation to stdout: %w", err)
		}
		res.OutputPath = "-"
		summaryOut = cmd.ErrOrStderr()
	} else {
		if err = os.MkdirAll(o.outDir, 0o750); err != nil {
			return fmt.Errorf("create output dir %s: %w", o.outDir, err)
		}
		path := filepath.Join(o.outDir, observationFilename(capturedAt))
		if err = os.WriteFile(path, out, 0o600); err != nil {
			return fmt.Errorf("write observation %s: %w", path, err)
		}
		res.OutputPath = path
	}

	if err = r.Render(summaryOut, res); err != nil {
		return fmt.Errorf("render summary: %w", err)
	}
	return nil
}

// readRawDir reads every top-level *.json file in dir into a name→bytes map.
func readRawDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read input dir %s: %w", dir, err)
	}
	files := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // dir is a user-provided input path
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		files[e.Name()] = b
	}
	return files, nil
}

// scaffoldDir is where --scaffold writes a new filter in a dev checkout.
const scaffoldDir = "internal/adapters/aws/transform/filters"

// scaffold writes a starter filter for name. In a dev checkout (the filters dir
// exists under cwd) it writes the file; otherwise it prints the skeleton to
// stdout so the contributor can save it themselves.
func scaffold(cmd *cobra.Command, name string) error {
	content := awstransform.ScaffoldContent(name, "REPLACE_TopLevelKey")
	if !dirExists(scaffoldDir) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", content)
		fmt.Fprintf(cmd.ErrOrStderr(),
			"# not in a stave checkout — save the above as %s/%s.jq\n", scaffoldDir, name)
		return nil
	}
	path := filepath.Join(scaffoldDir, name+".jq")
	if fileExists(path) {
		return &ui.UserError{Err: fmt.Errorf("filter already exists: %s", path)}
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write scaffold %s: %w", path, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", path)
	fmt.Fprintf(cmd.OutOrStdout(), "Next:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  1. Map the raw fields in %s\n", path)
	fmt.Fprintf(cmd.OutOrStdout(), "  2. Register the top-level key in topLevelKeyToFilter (detect.go)\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  3. Add a parity test against committed lab data (see docs/transform/CONTRIBUTING.md)\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  4. Verify: go test ./internal/adapters/aws/transform/ && stave transform --lint\n")
	return nil
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func countFatal(issues []awstransform.FilterIssue) int {
	n := 0
	for _, is := range issues {
		if is.Fatal {
			n++
		}
	}
	return n
}

// observationFilename derives the obs snapshot filename from captured_at,
// matching the observations naming convention (colons stripped):
// 2026-06-27T12:00:00Z -> 2026-06-27T120000Z.json
func observationFilename(capturedAt string) string {
	return strings.ReplaceAll(capturedAt, ":", "") + ".json"
}
