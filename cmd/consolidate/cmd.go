// Package consolidate implements the 'stave consolidate' command for
// multi-account security posture consolidation.
package consolidate

import (
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
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
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
			return run(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
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

	return cmd
}

func run(stdout, stderr io.Writer, opts *options) error {
	// History mode: org-level trending across multiple accounts.
	if opts.HistoryDir != "" {
		return runHistory(stdout, opts)
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
	chains, _ := ctlyaml.LoadChains(chainsDir)

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
	report, warnings, consolidateErr := appconsolidate.Run(appconsolidate.Input{
		Accounts:     accounts,
		Controls:     controls,
		ChainDefs:    chains,
		SLAConfig:    slaCfg,
		CELEvaluator: celEval,
		OrgName:      orgName,
		Now:          now,
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
		writeTextReport(out, report, opts.FocusAccount)
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
	data, err := os.ReadFile(path) //nolint:gosec // user-specified path
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
			AccountID:   accountID,
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

func writeTextReport(w io.Writer, r *appconsolidate.ConsolidatedReport, focusAccount string) {
	fmt.Fprintf(w, "ORGANIZATION SECURITY POSTURE\n")
	if r.OrgName != "" {
		fmt.Fprintf(w, "Organization: %s\n", r.OrgName)
	}
	fmt.Fprintf(w, "Accounts: %d  |  Assessed: %s\n\n",
		r.AccountCount, r.GeneratedAt.Format("2006-01-02 15:04 UTC"))

	fmt.Fprintf(w, "ACCOUNT RISK RANKING\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("\u2500", 85))
	fmt.Fprintf(w, "%-4s  %-24s %-12s %4s %4s %5s %4s %8s\n",
		"Rank", "Account", "Environment", "Crit", "High", "Chain", "SLA", "Score")
	fmt.Fprintf(w, "%s\n", strings.Repeat("\u2500", 85))

	for i := range r.Accounts {
		a := &r.Accounts[i]
		if focusAccount != "" && a.AccountID != focusAccount {
			continue
		}
		name := a.AccountName
		if len(name) > 24 {
			name = name[:21] + "..."
		}
		env := a.Environment
		if len(env) > 12 {
			env = env[:9] + "..."
		}
		fmt.Fprintf(w, "%4d  %-24s %-12s %4d %4d %5d %4d %8.0f\n",
			a.OrgRiskRank, name, env,
			a.CriticalCount, a.HighCount, a.ActiveChains, a.SLABreached, a.RiskScore)
	}

	fmt.Fprintf(w, "\nORG POSTURE SUMMARY\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("\u2500", 85))
	p := &r.OrgPosture
	fmt.Fprintf(w, "Total findings: %d  Critical: %d  Chains: %d  SLA breached: %d\n",
		p.TotalFindings, p.CriticalFindings, p.ChainFindings, p.SLABreached)
	if p.HighestRiskAccount != "" {
		fmt.Fprintf(w, "Highest risk account: %s\n", p.HighestRiskAccount)
	}
	if p.CrossAccountIdentities > 0 {
		fmt.Fprintf(w, "Cross-account identities: %d\n", p.CrossAccountIdentities)
	}

	if len(r.CrossAccount) > 0 {
		fmt.Fprintf(w, "\nCROSS-ACCOUNT FINDINGS (%d)\n", len(r.CrossAccount))
		fmt.Fprintf(w, "%s\n", strings.Repeat("\u2500", 85))
		for i := range r.CrossAccount {
			cf := &r.CrossAccount[i]
			sev := strings.ToUpper(cf.Severity)
			fmt.Fprintf(w, "[%s] %s\n", sev, cf.Type)
			fmt.Fprintf(w, "  %s/%s\n    \u2192 %s/%s\n",
				cf.SourceAccountID, cf.SourcePrincipal,
				cf.TargetAccountID, cf.TargetResource)
			fmt.Fprintf(w, "  %s\n\n", cf.Description)
		}
	}
}
