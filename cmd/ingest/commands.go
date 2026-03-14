package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	s3 "github.com/sufield/stave/internal/adapters/input/extract/s3"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Options holds ingest command flags.
type Options struct {
	Profile         string
	InputDir        string
	OutFile         string
	ScopeFile       string
	BucketAllowlist []string
	IncludeAll      bool
	Now             string
	Scrub           bool
	Force           bool
	DryRun          bool
	ListProfiles    bool
	OutDir          string
}

type ingestCommand struct {
	runtime *ui.Runtime
	opts    *Options
}

// NewIngestCmd builds the ingest command tree.
func NewIngestCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.DefaultRuntime()
	}

	opts := &Options{OutFile: "observations.json"}
	ic := &ingestCommand{runtime: rt, opts: opts}

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Convert source snapshots to normalized observations",
		Long: `Convert S3 bucket observations from an AWS configuration snapshot directory.

This command reads offline AWS CLI JSON exports and produces a normalized
observations file for evaluation.

Input: A directory containing AWS CLI JSON exports:
  - list-buckets.json (required)
  - get-bucket-tagging/<bucket>.json (optional)
  - get-bucket-policy/<bucket>.json (optional)
  - get-bucket-acl/<bucket>.json (optional)
  - get-public-access-block/<bucket>.json (optional)

Output: An observations JSON file (obs.v0.1 schema) suitable for evaluation.

Healthcare scope selection (default):
  - Tag: DataDomain=health
  - Tag: containsPHI=true
  - Or explicit bucket allowlist

No AWS API calls. Fully offline.
Deterministic when --now is set; uses wall clock for captured_at if omitted.

Output file safety:
  The output file will not be overwritten if it already exists.
  Use --force to overwrite an existing file.
  Use --dry-run to preview the output path without writing.

Examples:
  # Convert with profile (recommended)
  stave ingest --profile aws-s3 --input ./aws-snapshot --out observations.json

  # Convert with default health scope (tag-based)
  stave ingest --profile aws-s3 --input ./aws-snapshot --out observations.json

  # Convert specific buckets
  stave ingest --profile aws-s3 --input ./aws-snapshot --out obs.json --bucket-allowlist my-phi-bucket

  # Convert all buckets (no filtering)
  stave ingest --profile aws-s3 --input ./aws-snapshot --out obs.json --include-all

  # Preview output path without writing
  stave ingest --profile aws-s3 --input ./aws-snapshot --dry-run

  # Overwrite existing output file
  stave ingest --profile aws-s3 --input ./aws-snapshot --force

Next step: run control checks with stave apply.
See docs/s3-assessment.md for the complete S3 assessment workflow.` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ic.runIngest(cmd)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&opts.Profile, "profile", "p", "", "Extraction profile (e.g. aws-s3)")
	f.StringVar(&opts.InputDir, "input", "", "Path to AWS snapshot directory (required)")
	f.StringVar(&opts.OutFile, "out", opts.OutFile, "Path to output observations file")
	f.StringVar(&opts.ScopeFile, "scope", "", "Path to health scope config YAML file")
	f.StringSliceVar(&opts.BucketAllowlist, "bucket-allowlist", nil, "Bucket names/ARNs to include (can specify multiple)")
	f.BoolVar(&opts.IncludeAll, "include-all", false, "Disable health scope filtering (extract all buckets)")
	f.StringVar(&opts.Now, "now", "", "Override current time (RFC3339 format). Required for deterministic output.\n"+
		"If omitted, uses wall clock for captured_at timestamps (non-deterministic).")
	f.BoolVar(&opts.Scrub, "scrub", false, "Scrub sensitive fields (tags, raw policies, ACLs) from output for safe sharing")
	f.BoolVar(&opts.Force, "force", false, "Overwrite output file if it exists")
	f.BoolVar(&opts.DryRun, "dry-run", false, "Print planned output path without writing")
	f.BoolVar(&opts.ListProfiles, "list-profiles", false, "Show available ingest profiles and exit")
	f.StringVar(&opts.OutDir, "out-dir", "", "Directory for auto-named output file (mutually exclusive with --out)")

	return cmd
}

func (ic *ingestCommand) runIngest(cmd *cobra.Command) error {
	if ic.opts.ListProfiles {
		presenter := &RegistryPresenter{Stdout: cmd.OutOrStdout()}
		return presenter.RenderText()
	}
	if strings.TrimSpace(ic.opts.Profile) == "" {
		return fmt.Errorf("--profile is required (supported: aws-s3)")
	}
	if strings.TrimSpace(ic.opts.InputDir) == "" {
		return fmt.Errorf("--input is required")
	}

	profile, err := ParseProfile(ic.opts.Profile)
	if err != nil {
		return err
	}
	if profile != ProfileAWSS3 {
		return fmt.Errorf("unsupported --profile %q (supported: aws-s3)", ic.opts.Profile)
	}

	s3Cfg, err := ic.prepareS3Config(cmd)
	if err != nil {
		return err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	runner := &S3Runner{
		UI:     ic.runtime,
		Clock:  nil,
		Stdout: cmd.OutOrStdout(),
	}
	s3Cfg.TextOutput = gf.TextOutputEnabled()
	s3Cfg.AllowSymlinkOut = gf.AllowSymlinkOut
	s3Cfg.Force = ic.opts.Force || gf.Force

	return runner.Run(cmd.Context(), s3Cfg)
}

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
		InputDir:    snapshotDir,
		OutFile:     outFile,
		Now:         now,
		ScopeConfig: scopeConfig,
		Scrub:       ic.opts.Scrub,
		DryRun:      ic.opts.DryRun,
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
