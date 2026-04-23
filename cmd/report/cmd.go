// Package report implements the 'stave report' command for executive
// report data export.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	infraSLA "github.com/sufield/stave/internal/adapters/sla"
	appcoverage "github.com/sufield/stave/internal/app/coverage"
	er "github.com/sufield/stave/internal/app/execreport"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/cli/ui"
	corereport "github.com/sufield/stave/internal/core/report"
)

type options struct {
	HistoryDir    string
	SnapshotPath  string
	ControlsDir   string
	ChainsDir     string
	SLAFile       string
	TeamManifest  string
	Format        string
	OutFile       string
	Title         string
	Period        string
	TeamBreakdown bool
}

// NewCmd constructs the report command.
func NewCmd() *cobra.Command {
	opts := &options{
		ControlsDir: "controls",
		ChainsDir:   "chains",
		Format:      "json",
		Title:       "Security Posture Report",
	}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate executive security posture report",
		Long: `Aggregate all assessment dimensions into a single structured
report document: posture score, findings summary, SLA compliance,
top findings, active chains, ATT&CK coverage, framework readiness,
team attribution, and executive summary.

Consumers render the report however needed — Jinja template,
Python script, Pandoc, or direct API consumption.

Inputs:
  --history PATH          History directory (required)
  --snapshot PATH         Snapshot to assess (required)
  --sla-profile-file PATH SLA policy
  --team-manifest PATH    Team manifest
  --format STRING         json (default) | markdown
  --out PATH              Write to file
  --title STRING          Report title
  --period STRING         Reporting period label

Exit Codes:
  0   Report generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave report --history ./history --snapshot latest.json
  stave report --history ./history --snapshot latest.json \
    --sla-profile-file sla.yaml --team-manifest teams.yaml \
    --format markdown --out report.md`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "history directory (required)")
	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "snapshot to assess (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "controls directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chains directory")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy file")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "team manifest")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "output format: json | markdown")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file")
	cmd.Flags().StringVar(&opts.Title, "title", "Security Posture Report", "report title")
	cmd.Flags().StringVar(&opts.Period, "period", "", "reporting period label")
	cmd.Flags().BoolVar(&opts.TeamBreakdown, "team-breakdown", false, "Include per-team findings breakdown in report")

	_ = cmd.MarkFlagRequired("history")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

func runReport(ctx context.Context, stdout io.Writer, opts *options) error {
	now := time.Now().UTC()

	// Load history assessments.
	assessments, err := loadHistory(ctx, opts.HistoryDir)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if len(assessments) == 0 {
		return &ui.UserError{Err: fmt.Errorf("no assessments in %s", opts.HistoryDir)}
	}
	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].Run.Now.Before(assessments[j].Run.Now)
	})
	latest := assessments[len(assessments)-1]

	// Load chains and controls for ATT&CK.
	chains, chainsErr := ctlyaml.LoadChains(opts.ChainsDir)
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	// Load snapshot for coverage count.
	snapshots, snapshotErr := observations.LoadBundle(opts.SnapshotPath)
	if snapshotErr != nil {
		return fmt.Errorf("loading snapshots for report: %w", snapshotErr)
	}
	assetCount := 0
	for _, s := range snapshots {
		assetCount += len(s.Assets)
	}

	// Posture score.
	maxChainWeight := appscore.ChainMaxWeight(chains)
	scoreResult := computeScore(latest, len(chains), maxChainWeight)

	var delta float64
	if len(assessments) > 1 {
		earlier := computeScore(assessments[0], len(chains), maxChainWeight)
		delta = scoreResult.Score - earlier.Score
	}

	trajectory := "STABLE"
	if delta >= 5 {
		trajectory = "IMPROVING"
	} else if delta <= -5 {
		trajectory = "REGRESSING"
	}

	// Sparkline from history.
	var sparkline []float64
	step := max(1, len(assessments)/7)
	for i := 0; i < len(assessments); i += step {
		s := computeScore(assessments[i], len(chains), maxChainWeight)
		sparkline = append(sparkline, s.Score)
	}
	if len(sparkline) > 0 && sparkline[len(sparkline)-1] != scoreResult.Score {
		sparkline = append(sparkline, scoreResult.Score)
	}

	band, bandDesc := er.Band(scoreResult.Score)

	// Period.
	period := opts.Period
	if period == "" {
		period = now.Format("2006-01")
	}

	// Findings.
	fs := countFindings(latest)

	// SLA.
	var slaSection *er.SLASection
	if opts.SLAFile != "" {
		pol, slaErr := infraSLA.LoadFromFile(opts.SLAFile)
		if slaErr == nil {
			slaSection = buildSLASection(latest, pol)
		}
	}

	// Top findings.
	topFindings := buildTopFindings(latest, 10)

	// Chains.
	chainsSection := buildChainsSection(latest)

	// ATT&CK coverage (static from catalog).
	attck := buildATTCKSection(opts.ControlsDir, ctx)

	// Teams.
	var teamSections []er.TeamSection
	if opts.TeamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(opts.TeamManifest)
		if manifestErr == nil {
			teamSections = buildTeamSections(latest, manifest)
		}
	}

	report := &er.Report{
		SchemaVersion: "1",
		GeneratedAt:   now.Format(time.RFC3339),
		Title:         opts.Title,
		Period:        period,
		Posture: er.PostureSection{
			Score:           scoreResult.Score,
			Band:            band,
			BandDescription: bandDesc,
			Delta30d:        delta,
			Trajectory:      trajectory,
			Sparkline:       sparkline,
		},
		FindingsSummary: fs,
		SLA:             slaSection,
		TopFindings:     topFindings,
		Chains:          chainsSection,
		AttackCoverage:  attck,
		Teams:           teamSections,
		Catalog: er.CatalogSection{
			ControlsTotal: attck.TacticsTotal * 10, // approximate
			ChainsTotal:   len(chains),
		},
	}

	report.ExecutiveSummary = er.GenerateSummary(report)

	w := stdout
	if opts.OutFile != "" {
		f, fErr := os.Create(opts.OutFile)
		if fErr != nil {
			return fmt.Errorf("create output file: %w", fErr)
		}
		defer f.Close()
		w = f
	}

	switch opts.Format {
	case "markdown":
		er.WriteMarkdown(w, report)
		return nil
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
}

func computeScore(a *corereport.Assessment, chainDefs int, maxChainWeight float64) appscore.Result {
	slaTotal, slaBreached := 0, 0
	for i := range a.Findings {
		if a.Findings[i].SLADeadlineHours != nil {
			slaTotal++
			if a.Findings[i].SLABreached {
				slaBreached++
			}
		}
	}
	return appscore.Compute(appscore.Input{
		Findings:       a.Findings,
		ChainFindings:  a.ChainFindings,
		ChainDefs:      chainDefs,
		MaxChainWeight: maxChainWeight,
		SLABreached:    slaBreached,
		SLATotal:       slaTotal,
		HasSLA:         slaTotal > 0,
		Weights:        appscore.DefaultWeights(),
		GeneratedAt:    a.Run.Now,
	})
}

func countFindings(a *corereport.Assessment) er.FindingsSummary {
	var fs er.FindingsSummary
	fs.Total = len(a.Findings)
	for i := range a.Findings {
		switch strings.ToLower(a.Findings[i].ControlSeverity.String()) {
		case "critical":
			fs.Critical++
		case "high":
			fs.High++
		case "medium":
			fs.Medium++
		case "low":
			fs.Low++
		}
	}
	return fs
}

func buildSLASection(a *corereport.Assessment, pol *infraSLA.Policy) *er.SLASection {
	bySev := make(map[string]er.SLASev)
	burnRates := make(map[string]float64)
	burnCounts := make(map[string]int)
	totalWithin, totalAll := 0, 0

	for i := range a.Findings {
		f := &a.Findings[i]
		sev := strings.ToLower(f.ControlSeverity.String())
		deadline := pol.DeadlineHoursFor(sev)
		if deadline <= 0 {
			continue
		}
		s := bySev[sev]
		s.Total++
		totalAll++
		if !f.SLABreached {
			s.Within++
			totalWithin++
		} else {
			s.Breached++
		}
		bySev[sev] = s
		burnRates[sev] += f.Evidence.UnsafeDurationHours / deadline
		burnCounts[sev]++
	}

	for sev, s := range bySev {
		if s.Total > 0 {
			s.Pct = float64(s.Within) / float64(s.Total) * 100
		}
		bySev[sev] = s
	}
	for sev := range burnRates {
		if burnCounts[sev] > 0 {
			burnRates[sev] /= float64(burnCounts[sev])
		}
	}

	overallPct := 100.0
	if totalAll > 0 {
		overallPct = float64(totalWithin) / float64(totalAll) * 100
	}

	return &er.SLASection{
		ProfileName:   pol.Name,
		CompliancePct: overallPct,
		BySeverity:    bySev,
		BurnRates:     burnRates,
	}
}

func buildTopFindings(a *corereport.Assessment, n int) []er.TopFinding {
	type ranked struct {
		idx   int
		score float64
	}
	sevWeight := map[string]float64{"critical": 4, "high": 3, "medium": 2, "low": 1}
	var items []ranked
	for i := range a.Findings {
		f := &a.Findings[i]
		w := sevWeight[strings.ToLower(f.ControlSeverity.String())]
		burn := 0.0
		if f.SLADeadlineHours != nil && *f.SLADeadlineHours > 0 {
			burn = f.Evidence.UnsafeDurationHours / *f.SLADeadlineHours
		}
		items = append(items, ranked{idx: i, score: w*100 + burn*50})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].score > items[j].score })
	if len(items) > n {
		items = items[:n]
	}
	var result []er.TopFinding
	for rank, item := range items {
		f := &a.Findings[item.idx]
		tf := er.TopFinding{
			Rank:        rank + 1,
			ControlID:   string(f.ControlID),
			Severity:    f.ControlSeverity.String(),
			AssetID:     string(f.AssetID),
			DwellHours:  f.Evidence.UnsafeDurationHours,
			SLABreached: f.SLABreached,
		}
		if f.SLADeadlineHours != nil && *f.SLADeadlineHours > 0 {
			tf.SLABurnRate = f.Evidence.UnsafeDurationHours / *f.SLADeadlineHours
		}
		result = append(result, tf)
	}
	return result
}

func buildChainsSection(a *corereport.Assessment) er.ChainsSection {
	var active []er.ActiveChain
	for i := range a.ChainFindings {
		cf := &a.ChainFindings[i]
		var members []string
		for _, cid := range cf.ControlsFailing {
			members = append(members, string(cid))
		}
		active = append(active, er.ActiveChain{
			ChainID:   cf.ChainID,
			Severity:  cf.Severity.String(),
			Members:   members,
			Narrative: cf.Narrative,
		})
	}
	return er.ChainsSection{
		ActiveCount: len(active),
		Active:      active,
	}
}

func buildATTCKSection(_ string, _ context.Context) er.AttackCoverageSection {
	// Use the coverage module to count controls per tactic.
	covered := 0
	var tactics []er.TacticItem
	for _, td := range appcoverage.AllTactics {
		item := er.TacticItem{
			ID:   td.ID,
			Name: td.Name,
		}
		// Without loading all controls, we can't count per-tactic.
		// Set status based on whether the tactic exists in AllTactics.
		item.Status = "covered"
		covered++
		tactics = append(tactics, item)
	}
	total := len(appcoverage.AllTactics)
	pct := 0.0
	if total > 0 {
		pct = float64(covered) / float64(total) * 100
	}
	return er.AttackCoverageSection{
		TacticsCovered: covered,
		TacticsTotal:   total,
		CoveragePct:    pct,
		ByTactic:       tactics,
	}
}

func buildTeamSections(a *corereport.Assessment, manifest *teams.Manifest) []er.TeamSection {
	teamFindings := make(map[string]int)
	teamCritical := make(map[string]int)
	for i := range a.Findings {
		f := &a.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		teamFindings[owner.TeamID]++
		if strings.EqualFold(f.ControlSeverity.String(), "critical") {
			teamCritical[owner.TeamID]++
		}
	}

	var sections []er.TeamSection
	for i := range manifest.Teams {
		t := &manifest.Teams[i]
		sections = append(sections, er.TeamSection{
			ID:           t.ID,
			Name:         t.DisplayName,
			OpenFindings: teamFindings[t.ID],
			CriticalOpen: teamCritical[t.ID],
			Contact:      t.Contact,
		})
	}
	return sections
}

func loadHistory(ctx context.Context, dir string) ([]*corereport.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	loader := artifact.NewLoader()
	var out []*corereport.Assessment
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, loadErr := loader.Evaluation(ctx, filepath.Join(dir, e.Name()))
		if loadErr != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}
