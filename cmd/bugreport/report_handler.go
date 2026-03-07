package bugreport

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	supportapp "github.com/sufield/stave/internal/app/support"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var (
	reportOut     string
	tailLines     int
	includeConfig bool
)

func runReport(cmd *cobra.Command, _ []string) error {
	_, err := supportapp.RunBugReport(supportapp.BugReportDeps{
		PrepareOutput: func() (supportapp.PreparedOutput, error) {
			return prepareOutputFile(cmd)
		},
		PopulateBundle: func(zw *zip.Writer, cwd string) error {
			return populateBundle(cmd, zw, cwd)
		},
		WriteSummary: func(outPath string) error {
			return writeSummary(cmd, outPath)
		},
	})
	return err
}

func prepareOutputFile(cmd *cobra.Command) (supportapp.PreparedOutput, error) {
	if tailLines < 0 {
		return supportapp.PreparedOutput{}, &ui.InputError{Err: fmt.Errorf("invalid --tail-lines %d: must be >= 0", tailLines)}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return supportapp.PreparedOutput{}, fmt.Errorf("resolve current directory: %w", err)
	}
	outPath := fsutil.CleanUserPath(resolveOutPath(cwd, reportOut))
	if dirErr := ensureBundleDir(cmd, outPath); dirErr != nil {
		return supportapp.PreparedOutput{}, dirErr
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = cmdutil.ForceEnabled(cmd)
	opts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
	zipFile, err := fsutil.SafeCreateFile(outPath, opts)
	if err != nil {
		return supportapp.PreparedOutput{}, fmt.Errorf("create bundle: %w", err)
	}
	return supportapp.PreparedOutput{Cwd: cwd, OutPath: outPath, File: zipFile}, nil
}

func populateBundle(cmd *cobra.Command, zw *zip.Writer, cwd string) error {
	bundle := newBundleWriter(zw)
	if err := addCoreArtifacts(bundle, cwd); err != nil {
		return err
	}
	if includeConfig {
		if err := addConfigArtifact(bundle); err != nil {
			return err
		}
	}
	if err := addLogArtifact(cmd, bundle, cwd); err != nil {
		return err
	}
	return addManifest(bundle)
}

func writeSummary(cmd *cobra.Command, outPath string) error {
	if cmdutil.QuietEnabled(cmd) {
		return nil
	}
	w := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(w, "Created diagnostic bundle: %s\n", outPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Attach this file when filing an issue: %s\n", metadata.CLIIssuesURL); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\nTo view bundle contents:\n  stave bug-report inspect %s\n", outPath)
	return err
}

func ensureBundleDir(cmd *cobra.Command, outPath string) error {
	dir := filepath.Dir(outPath)
	if strings.TrimSpace(dir) == "" || dir == "." {
		return nil
	}
	if err := fsutil.SafeMkdirAll(dir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd)}); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	return nil
}

func resolveOutPath(cwd, rawOut string) string {
	cleaned := strings.TrimSpace(rawOut)
	if cleaned != "" {
		return cleaned
	}
	name := "stave-diag-" + time.Now().UTC().Format("20060102T150405Z") + ".zip"
	return filepath.Join(cwd, name)
}
