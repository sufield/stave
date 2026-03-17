package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	s3 "github.com/sufield/stave/internal/adapters/input/extract/s3"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func (ic *ingestCommand) prepareS3Config(cmd *cobra.Command) (S3Config, error) {
	if ic.opts.OutDir != "" && cmd.Flags().Changed("out") {
		return S3Config{}, fmt.Errorf("--out and --out-dir are mutually exclusive")
	}

	snapshotDir := fsutil.CleanUserPath(ic.opts.InputDir)
	scopeFile := fsutil.CleanUserPath(ic.opts.ScopeFile)
	outFile := fsutil.CleanUserPath(ic.opts.OutFile)
	outDir := fsutil.CleanUserPath(ic.opts.OutDir)

	now, err := compose.ResolveNow(ic.opts.Now)
	if err != nil {
		return S3Config{}, err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	if outDir != "" {
		if mkErr := fsutil.SafeMkdirAll(outDir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: gf.AllowSymlinkOut}); mkErr != nil {
			return S3Config{}, fmt.Errorf("create --out-dir: %w", mkErr)
		}
		outFile = filepath.Join(outDir, now.UTC().Format(time.RFC3339)+".json")
	}

	if writableErr := ensureOutputWritable(outFile, ic.opts.Force || gf.Force, ic.opts.DryRun); writableErr != nil {
		return S3Config{}, writableErr
	}
	if inputErr := validateInputDir(snapshotDir); inputErr != nil {
		return S3Config{}, inputErr
	}

	scopeConfig, err := resolveScopeConfig(ic.opts.IncludeAll, ic.opts.BucketAllowlist, scopeFile)
	if err != nil {
		return S3Config{}, err
	}

	return S3Config{
		InputDir:        snapshotDir,
		OutFile:         outFile,
		Now:             now,
		ScopeConfig:     scopeConfig,
		Scrub:           ic.opts.Scrub,
		DryRun:          ic.opts.DryRun,
		Force:           ic.opts.Force || gf.Force,
		TextOutput:      gf.TextOutputEnabled(),
		AllowSymlinkOut: gf.AllowSymlinkOut,
	}, nil
}

func ensureOutputWritable(path string, overwrite, dryRun bool) error {
	if overwrite || dryRun {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("output file already exists: %s (use --force to overwrite)", path)
	}
	return nil
}

func validateInputDir(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("--input not accessible: %s: %w", path, err)
	}
	return nil
}

func resolveScopeConfig(includeAll bool, bucketAllowlist []string, scopeFile string) (*s3.ScopeConfig, error) {
	if includeAll {
		return &s3.ScopeConfig{IncludeAll: true}, nil
	}
	if len(bucketAllowlist) > 0 {
		return s3.NewScopeConfigFromAllowlist(bucketAllowlist), nil
	}
	if scopeFile != "" {
		cfg, err := s3.NewScopeConfigFromFile(scopeFile)
		if err != nil {
			return nil, fmt.Errorf("--scope file error: %w", err)
		}
		return cfg, nil
	}
	return s3.DefaultScopeConfig(), nil
}
