package bugreport

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type reportFlags struct {
	out           string
	tailLines     int
	includeConfig bool
}

type preparedOutput struct {
	cwd     string
	outPath string
	file    io.WriteCloser
}

func runReport(cmd *cobra.Command, flags *reportFlags) error {
	prepared, err := prepareOutputFile(cmd, flags)
	if err != nil {
		return err
	}
	defer prepared.file.Close()

	zw := zip.NewWriter(prepared.file)
	if err := populateBundle(cmd, zw, prepared.cwd, flags); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finalize bundle: %w", err)
	}
	return writeSummary(cmd, prepared.outPath)
}

func prepareOutputFile(cmd *cobra.Command, flags *reportFlags) (preparedOutput, error) {
	if flags.tailLines < 0 {
		return preparedOutput{}, &ui.InputError{Err: fmt.Errorf("invalid --tail-lines %d: must be >= 0", flags.tailLines)}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return preparedOutput{}, fmt.Errorf("resolve current directory: %w", err)
	}
	outPath := fsutil.CleanUserPath(resolveOutPath(cwd, flags.out))
	zipFile, err := cmdutil.CreateOutputFile(cmd, outPath)
	if err != nil {
		return preparedOutput{}, err
	}
	return preparedOutput{cwd: cwd, outPath: outPath, file: zipFile}, nil
}

func populateBundle(cmd *cobra.Command, zw *zip.Writer, cwd string, flags *reportFlags) error {
	bundle := newBundleWriter(zw)
	if err := addCoreArtifacts(bundle, cwd); err != nil {
		return err
	}
	if flags.includeConfig {
		if err := addConfigArtifact(bundle); err != nil {
			return err
		}
	}
	if err := addLogArtifact(cmd, bundle, cwd, flags.tailLines); err != nil {
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

func resolveOutPath(cwd, rawOut string) string {
	cleaned := strings.TrimSpace(rawOut)
	if cleaned != "" {
		return cleaned
	}
	name := "stave-diag-" + time.Now().UTC().Format("20060102T150405Z") + ".zip"
	return filepath.Join(cwd, name)
}
