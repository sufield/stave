// Package report implements the 'stave report' command for executive
// report data export.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/sufield/stave/internal/app/contracts"
	appcoverage "github.com/sufield/stave/internal/app/coverage"
	er "github.com/sufield/stave/internal/app/execreport"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/builtin/capabilities"
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
	Format        contracts.OutputFormat
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
		Format:      contracts.FormatJSON,
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
	cmd.Flags().VarP(&opts.Format, "format", "f", "output format: json | markdown")
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
	chains, chainsErr := ctlyaml.LoadChains(opts.ChainsDir, capabilities.Builtin())
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

	// 30-day trajectory: compare the latest score to the assessment
	// closest to (now - 30 days). Earlier shape compared against
	// assessments[0] (the *oldest-ever* assessment), which made delta
	// drift unboundedly with history depth — a healthy fortnight
	// looked indistinguishable from a quarter of slow regression.
	// Fallback when no assessment lies within the 30-day window: use
	// the oldest available, but only when the history has more than
	// one entry so a single-data-point report still computes delta=0.
	var delta float64
	if earlier, ok := assessmentClosestTo(assessments, now.AddDate(0, 0, -30)); ok {
		earlierScore := computeScore(earlier, len(chains), maxChainWeight)
		delta = scoreResult.Score - earlierScore.Score
	}

	trajectory := er.TrajectoryStable
	if delta >= 5 {
		trajectory = er.TrajectoryImproving
	} else if delta <= -5 {
		trajectory = er.TrajectoryRegressing
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

	// SLA. The flag is opt-in: when not provided, the report omits
	// the SLA section. When provided but the file fails to load, the
	// operator gave us an explicit input and we must not silently
	// drop it — surface as a UserError so they see what went wrong
	// rather than receive a report that quietly omits SLA content.
	var slaSection *er.SLASection
	if opts.SLAFile != "" {
		pol, slaErr := infraSLA.LoadFromFile(opts.SLAFile)
		if slaErr != nil {
			return &ui.UserError{Err: fmt.Errorf("load --sla-profile-file %q: %w", opts.SLAFile, slaErr)}
		}
		slaSection = buildSLASection(latest, pol)
	}

	// Top findings.
	topFindings := buildTopFindings(latest, 10)

	// Chains.
	chainsSection := buildChainsSection(latest)

	// ATT&CK coverage (static from catalog).
	attck := buildATTCKSection(ctx, opts.ControlsDir)

	// Honest ControlsTotal: count what's actually loaded from
	// opts.ControlsDir. Falling back to the previous TacticsTotal*10
	// approximation produced fabricated metrics that the executive
	// report consumer treated as ground truth — a 14-tactic catalog
	// reported as "140 controls total" regardless of reality.
	controlsTotal := 0
	if opts.ControlsDir != "" {
		ctlLoader := ctlyaml.NewControlLoader()
		loaded, loadErr := ctlLoader.LoadControls(ctx, opts.ControlsDir)
		if loadErr != nil {
			// The earlier shape silently dropped the error and left
			// controlsTotal at 0, which produced a "0 controls" line
			// in the report whenever the controls directory was
			// unreadable. Operators couldn't tell whether the
			// catalog was empty or the path was wrong. The user
			// passed an explicit --controls path here, so the
			// failure is a configuration/bug we surface as a hard
			// error — silent zeros are worse than a clear stop.
			return &ui.UserError{Err: fmt.Errorf("load controls from %q: %w", opts.ControlsDir, loadErr)}
		}
		controlsTotal = len(loaded)
	}

	// Teams. Same opt-in / explicit-failure split as --sla-profile-file:
	// flag absent → omit section; flag present but load fails → surface
	// to the operator instead of producing a report without team
	// attribution.
	var teamSections []er.TeamSection
	if opts.TeamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(opts.TeamManifest)
		if manifestErr != nil {
			return &ui.UserError{Err: fmt.Errorf("load --team-manifest %q: %w", opts.TeamManifest, manifestErr)}
		}
		teamSections = buildTeamSections(latest, manifest)
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
			ControlsTotal: controlsTotal,
			ChainsTotal:   len(chains),
		},
	}

	report.ExecutiveSummary = er.GenerateSummary(report)

	w := stdout
	var f *os.File
	if opts.OutFile != "" {
		var fErr error
		f, fErr = os.Create(opts.OutFile)
		if fErr != nil {
			return fmt.Errorf("create output file: %w", fErr)
		}
		w = f
	}

	var writeErr error
	switch opts.Format {
	case contracts.FormatMarkdown:
		writeErr = er.WriteMarkdown(w, report)
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		writeErr = enc.Encode(report)
	}

	// Close-error handling: surface the close error only when the write
	// itself succeeded. A failed write already fully describes the
	// problem; chaining a "file already closed" / "broken pipe" close
	// error on top obscures the real cause. See `defer f.Close()`
	// audit — silent-close hid truncated outputs on disk.
	if f != nil {
		closeErr := f.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
	}
	return writeErr
}

// assessmentClosestTo returns the assessment whose Run.Now is closest
// (in absolute time) to target. Assumes the input slice is sorted
// ascending by Run.Now (loadHistory + sort above guarantees this).
// Returns (_, false) when:
//   - the slice is empty, or
//   - the slice has only the latest assessment, since a single-point
//     history has no "earlier" to compare against and falling back to
//     comparing the latest with itself would always report delta=0
//     in a way that could mask the absence of trend data.
func assessmentClosestTo(assessments []*corereport.Assessment, target time.Time) (*corereport.Assessment, bool) {
	if len(assessments) < 2 {
		return nil, false
	}
	// Exclude the latest entry; "earlier than now" is the meaningful
	// reference for a delta calculation, and including the latest
	// would make a same-day report compare against itself.
	candidates := assessments[:len(assessments)-1]
	best := candidates[0]
	bestDiff := absDuration(best.Run.Now.Sub(target))
	for _, a := range candidates[1:] {
		diff := absDuration(a.Run.Now.Sub(target))
		if diff < bestDiff {
			best = a
			bestDiff = diff
		}
	}
	return best, true
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
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

	// Coverage scoring: average framework readiness across whatever
	// frameworks the assessment reports. Without this, the score's
	// 10% coverage weight always credited as 1.0 (perfect coverage)
	// because HasCoverage / CoveragePct were never set — an
	// assessment with zero compliance evaluation appeared to have
	// perfect compliance coverage. When no FrameworkReadiness data
	// is available, signal that explicitly so the score-weight
	// system can decline the credit instead of defaulting to perfect.
	var coveragePct float64
	hasCoverage := false
	if len(a.Summary.FrameworkReadiness) > 0 {
		var total float64
		for _, fr := range a.Summary.FrameworkReadiness {
			total += float64(fr.ReadinessPercent)
		}
		coveragePct = total / float64(len(a.Summary.FrameworkReadiness))
		hasCoverage = true
	}

	return appscore.Compute(appscore.Input{
		Findings:       a.Findings,
		ChainFindings:  a.ChainFindings,
		ChainDefs:      chainDefs,
		MaxChainWeight: maxChainWeight,
		SLABreached:    slaBreached,
		SLATotal:       slaTotal,
		CoveragePct:    coveragePct,
		HasSLA:         slaTotal > 0,
		HasCoverage:    hasCoverage,
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
			ChainID:   string(cf.ChainID),
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

func buildATTCKSection(ctx context.Context, controlsDir string) er.AttackCoverageSection {
	total := len(appcoverage.AllTactics)

	// Without controls, we cannot honestly say what's covered. Fall
	// back to a fully-uncovered report rather than the previous
	// "every tactic is covered" lie that depended on nothing but
	// the tactic catalog being non-empty.
	emptyReport := func(status string) er.AttackCoverageSection {
		tactics := make([]er.TacticItem, 0, total)
		for _, td := range appcoverage.AllTactics {
			tactics = append(tactics, er.TacticItem{
				ID:     td.ID,
				Name:   td.Name,
				Status: status,
			})
		}
		return er.AttackCoverageSection{
			TacticsCovered: 0,
			TacticsTotal:   total,
			CoveragePct:    0,
			ByTactic:       tactics,
		}
	}

	if controlsDir == "" {
		return emptyReport("not_covered")
	}
	loader := ctlyaml.NewControlLoader()
	controls, err := loader.LoadControls(ctx, controlsDir)
	if err != nil {
		return emptyReport("not_covered")
	}

	report := appcoverage.Build(appcoverage.BuildInput{Controls: controls})
	tacticItems := make([]er.TacticItem, 0, len(report.Tactics))
	covered := 0
	for i := range report.Tactics {
		tc := &report.Tactics[i]
		// "covered" / "thin" both count as covered for the rolled-up
		// pct; "no_coverage" maps to "not_covered" in the section's
		// vocabulary.
		status := tc.Status
		if status == "no_coverage" {
			status = "not_covered"
		}
		if tc.Status == "covered" || tc.Status == "thin" {
			covered++
		}
		tacticItems = append(tacticItems, er.TacticItem{
			ID:     tc.TacticID,
			Name:   tc.TacticName,
			Status: status,
		})
	}
	pct := 0.0
	if total > 0 {
		pct = float64(covered) / float64(total) * 100
	}
	return er.AttackCoverageSection{
		TacticsCovered: covered,
		TacticsTotal:   total,
		CoveragePct:    pct,
		ByTactic:       tacticItems,
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
	skipped := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			// History files that fail to parse are non-fatal — skip them
			// so a single corrupt artifact does not blank the whole
			// historical view — but log so operators can find and fix
			// the bad file. Silent skip masked corrupt rotations for
			// long enough that the report would just trim its time
			// series and look like nothing was wrong.
			slog.Warn("report: skipping corrupt history file", "path", path, "err", loadErr)
			skipped++
			continue
		}
		out = append(out, a)
	}
	// All-skipped is different from "directory was empty": empty
	// dir is a fresh setup ("nothing to report yet"), all-skipped
	// is corrupt rotations that need an operator's eyes. Surface
	// the gap as an error so the report doesn't silently render
	// an empty trend chart on top of broken inputs.
	if len(out) == 0 && skipped > 0 {
		return nil, fmt.Errorf("no valid assessments in %s (%d files skipped due to errors)", dir, skipped)
	}
	return out, nil
}
