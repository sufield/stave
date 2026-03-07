package ingest

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
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

// IngestCmd is the package-level command for existing callers.
var IngestCmd = NewIngestCmd(ui.NewRuntime(nil, nil))

// NewIngestCmd builds the ingest command tree.
func NewIngestCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.NewRuntime(nil, nil)
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
		printIngestProfiles(cmd.OutOrStdout())
		return nil
	}
	if strings.TrimSpace(ic.opts.Profile) == "" {
		return fmt.Errorf("--profile is required (supported: aws-s3)")
	}
	if strings.TrimSpace(ic.opts.InputDir) == "" {
		return fmt.Errorf("--input is required")
	}

	profile, err := parseIngestProfile(ic.opts.Profile)
	if err != nil {
		return err
	}
	if profile != ingestProfileAWSS3 {
		return fmt.Errorf("unsupported --profile %q (supported: aws-s3)", ic.opts.Profile)
	}

	runner := newS3Runner(ic.runtime, ic.opts)
	return runner.run(cmd)
}
