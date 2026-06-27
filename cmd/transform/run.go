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

// observationFilename derives the obs snapshot filename from captured_at,
// matching the observations naming convention (colons stripped):
// 2026-06-27T12:00:00Z -> 2026-06-27T120000Z.json
func observationFilename(capturedAt string) string {
	return strings.ReplaceAll(capturedAt, ":", "") + ".json"
}
