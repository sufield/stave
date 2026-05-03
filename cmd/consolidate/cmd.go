// Package consolidate implements the 'stave consolidate' command for
// multi-account security posture consolidation.
package consolidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	builtinctl "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/sla"
	appconsolidate "github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/builtin/capabilities"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

type options struct {
	SnapshotsDir   string
	ManifestFile   string
	OrgName        string
	Format         string
	SLAProfile     string
	SLAProfileFile string
	OutPath        string
	FocusAccount   string
	Now            string
	HistoryDir     string
	Window         string
	DiffControl    string
	Top            int
}

// NewCmd constructs the consolidate command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "consolidate",
		Short: "Multi-account security posture consolidation",
		Long: `Consolidate reads snapshots from multiple AWS accounts and produces
an organization-level security posture view with cross-account finding
correlation, org-level risk ranking, and per-account summaries.

Inputs:
  --snapshots DIR     Directory containing per-account snapshot files
  --manifest FILE     YAML manifest with account metadata and snapshot paths
  --sla-profile NAME  SLA policy profile (default: default)
  --format FORMAT     table (default) | json

Exit Codes:
  0   Consolidation complete
  2   Input error`,
		Example: `  stave consolidate --snapshots ./org-snapshots/
  stave consolidate --manifest org.yaml --sla-profile hipaa
  stave consolidate --snapshots ./org-snapshots/ --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotsDir, "snapshots", "", "Directory containing per-account snapshot files")
	cmd.Flags().StringVar(&opts.ManifestFile, "manifest", "", "YAML manifest with account metadata")
	cmd.Flags().StringVar(&opts.OrgName, "org-name", "", "Organization name for output labeling")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: table or json")
	cmd.Flags().StringVar(&opts.SLAProfile, "sla-profile", "", "SLA policy profile")
	cmd.Flags().StringVar(&opts.SLAProfileFile, "sla-profile-file", "", "path to custom SLA policy YAML file")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "Write output to file instead of stdout")
	cmd.Flags().StringVar(&opts.FocusAccount, "focus-account", "", "Show detail for a specific account")
	cmd.Flags().StringVar(&opts.Now, "now", "", "Override current time (RFC3339)")
	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "Directory of per-account assessment history for org trending")
	cmd.Flags().StringVar(&opts.Window, "window", "90d", "Lookback window for trend calculation (e.g. 90d)")
	cmd.Flags().StringVar(&opts.DiffControl, "diff-control", "", "Run outlier analysis for a specific control (requires --history)")
	cmd.Flags().IntVar(&opts.Top, "top", 0, "Limit failing account output to N entries")

	return cmd
}

func run(ctx context.Context, stdout, stderr io.Writer, opts *options) error {
	// Diff mode: cross-account outlier analysis for a specific control.
	if opts.DiffControl != "" {
		return runDiff(ctx, stdout, opts)
	}

	// History mode: org-level trending across multiple accounts.
	if opts.HistoryDir != "" {
		return runHistory(ctx, stdout, opts)
	}

	if opts.SnapshotsDir == "" && opts.ManifestFile == "" {
		return errors.New("one of --snapshots, --manifest, or --history is required")
	}

	// Load accounts.
	accounts, orgName, err := loadAccounts(opts)
	if err != nil {
		return fmt.Errorf("load accounts: %w", err)
	}
	if orgName == "" {
		orgName = opts.OrgName
	}

	// Load built-in controls and chains.
	store := builtinctl.NewControlStore(controldata.FS, ".")
	controls, err := store.All()
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}
	chainsDir := "chains"
	chains, chainsErr := ctlyaml.LoadChains(chainsDir, capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	// Load SLA config — file takes precedence.
	var slaCfg *evaluation.SLAConfig
	var slaPol *sla.Policy
	if opts.SLAProfileFile != "" {
		pol, slaErr := sla.LoadFromFile(opts.SLAProfileFile)
		if slaErr != nil {
			return fmt.Errorf("load sla profile file: %w", slaErr)
		}
		slaPol = pol
	} else if opts.SLAProfile != "" {
		pol, slaErr := sla.LoadEmbedded(opts.SLAProfile)
		if slaErr != nil {
			return fmt.Errorf("load sla profile: %w", slaErr)
		}
		slaPol = pol
	}
	if slaPol != nil {
		slaCfg = &evaluation.SLAConfig{
			ProfileID: slaPol.ID,
			DeadlineBySeverity: map[string]float64{
				"critical": slaPol.DeadlineHoursFor("critical"),
				"high":     slaPol.DeadlineHoursFor("high"),
				"medium":   slaPol.DeadlineHoursFor("medium"),
				"low":      slaPol.DeadlineHoursFor("low"),
			},
			EscalationFactor: slaPol.EscalationFactor,
		}
	}

	now := time.Now().UTC()
	if opts.Now != "" {
		now, err = time.Parse(time.RFC3339, opts.Now)
		if err != nil {
			return fmt.Errorf("parse --now: %w", err)
		}
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return fmt.Errorf("init cel evaluator: %w", err)
	}

	// Run consolidation.
	report, warnings, consolidateErr := appconsolidate.Run(ctx, appconsolidate.Input{
		Accounts:                 accounts,
		Controls:                 controls,
		ChainDefs:                chains,
		SLAConfig:                slaCfg,
		CELEvaluator:             celEval,
		OrgName:                  orgName,
		Now:                      now,
		AccountIDFromARN:         iam.ExtractAccountID,
		BuildResourceAccessIndex: iam.BuildResourceAccessIndex,
	})
	if consolidateErr != nil {
		return consolidateErr
	}

	// Emit warnings to stderr.
	for _, w := range warnings {
		fmt.Fprintf(stderr, "Warning: %s\n", w)
	}

	// Output.
	out := stdout
	if opts.OutPath != "" {
		f, createErr := os.Create(opts.OutPath)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default:
		appconsolidate.WriteTextReport(out, report, opts.FocusAccount)
		return nil
	}
}

func loadAccounts(opts *options) ([]appconsolidate.AccountInput, string, error) {
	if opts.ManifestFile != "" {
		return loadFromManifest(opts.ManifestFile)
	}
	return loadFromDirectory(opts.SnapshotsDir)
}

func loadFromManifest(path string) ([]appconsolidate.AccountInput, string, error) {
	data, err := os.ReadFile(fsutil.CleanUserPath(path)) //nolint:gosec // user-specified path
	if err != nil {
		return nil, "", fmt.Errorf("read manifest: %w", err)
	}
	var manifest appconsolidate.AccountManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, "", fmt.Errorf("parse manifest: %w", err)
	}

	baseDir := filepath.Dir(path)
	var accounts []appconsolidate.AccountInput
	for _, entry := range manifest.Accounts {
		snapPath := entry.Snapshot
		if !filepath.IsAbs(snapPath) {
			snapPath = filepath.Join(baseDir, snapPath)
		}
		snaps, loadErr := observations.LoadBundle(snapPath)
		if loadErr != nil {
			return nil, "", fmt.Errorf("account %s: %w", entry.AccountID, loadErr)
		}
		accounts = append(accounts, appconsolidate.AccountInput{
			AccountID:    entry.AccountID,
			AccountName:  entry.AccountName,
			Environment:  entry.Environment,
			BusinessUnit: entry.BusinessUnit,
			Snapshots:    snaps,
		})
	}
	return accounts, manifest.Organization, nil
}

func loadFromDirectory(dir string) ([]appconsolidate.AccountInput, string, error) {
	dir = fsutil.CleanUserPath(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("read directory: %w", err)
	}

	var accounts []appconsolidate.AccountInput
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		snaps, loadErr := observations.LoadBundle(path)
		if loadErr != nil {
			continue // skip non-snapshot files
		}
		if len(snaps) == 0 {
			continue
		}

		// Derive account ID from first asset ARN.
		accountID := deriveAccountID(snaps)
		if accountID == "" {
			accountID = strings.TrimSuffix(entry.Name(), ".json")
		}

		accounts = append(accounts, appconsolidate.AccountInput{
			AccountID:   appconsolidate.AccountID(accountID),
			AccountName: accountID,
			Snapshots:   snaps,
		})
	}
	if len(accounts) == 0 {
		return nil, "", errors.New("no valid snapshot files found in directory")
	}
	return accounts, "", nil
}

func deriveAccountID(snaps []asset.Snapshot) string {
	for i := range snaps {
		for j := range snaps[i].Assets {
			parts := strings.Split(string(snaps[i].Assets[j].ID), ":")
			if len(parts) >= 5 && parts[4] != "" {
				return parts[4]
			}
		}
	}
	return ""
}
