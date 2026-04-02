package bugreport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runReport(cmd *cobra.Command, opts reportOptions) error {
	gf := cliflags.GetGlobalFlags(cmd)

	if opts.tailLines < 0 {
		return &ui.UserError{Err: fmt.Errorf("invalid --tail-lines %d: must be >= 0", opts.tailLines)}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	outPath := fsutil.CleanUserPath(ResolveDefaultOutPath(cwd, opts.out, time.Now().UTC()))
	f, err := fileout.OpenOutputFile(outPath, fileout.FileOptions{
		Overwrite:     gf.Force,
		AllowSymlinks: gf.AllowSymlinkOut,
		DirPerms:      0o700,
	})
	if err != nil {
		return err
	}
	defer f.Close()

	binaryPath, _ := os.Executable()

	var configPath string
	if opts.includeConfig {
		if p, ok := findConfigPath(); ok {
			configPath = p
		}
	}

	logCandidates := make([]string, 0, 2)
	if p := strings.TrimSpace(gf.LogFile); p != "" {
		logCandidates = append(logCandidates, fsutil.CleanUserPath(p))
	}
	logCandidates = append(logCandidates, filepath.Join(cwd, "stave.log"))

	var logPath string
	if p, ok := FindLogPath(logCandidates...); ok {
		logPath = p
	}

	gen := NewGenerator()
	if err := gen.Generate(cmd.Context(), f, Config{
		Cwd:          cwd,
		BinaryPath:   binaryPath,
		ConfigPath:   configPath,
		LogPath:      logPath,
		LogTailLines: opts.tailLines,
		Args:         os.Args,
		Env:          os.Environ(),
	}); err != nil {
		return err
	}

	if !gf.Quiet {
		if absOut, absErr := filepath.Abs(outPath); absErr == nil {
			outPath = absOut
		}
		WriteSummary(cmd.OutOrStdout(), outPath)
	}
	return nil
}
