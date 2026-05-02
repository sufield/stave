package execreport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/builtin/capabilities"
	corereport "github.com/sufield/stave/internal/core/report"
)

// BuilderDeps wires the ports the executive-report builder needs.
// All fields are required when the corresponding [BuilderInput]
// path is exercised — Builder fails loud rather than silently
// rendering partial reports if a port is nil.
type BuilderDeps struct {
	ArtifactLoader       appcontracts.ArtifactLoader
	ChainLoader          appcontracts.ChainDefinitionLoader
	SLAProvider          appcontracts.SLAProvider
	SnapshotBundleLoader appcontracts.SnapshotBundleLoader
	ControlRepo          appcontracts.ControlRepository
}

// BuilderInput captures the per-run flags / paths the cmd/report
// surface accepts. Empty optional fields disable their corresponding
// section (SLA, teams).
type BuilderInput struct {
	HistoryDir       string
	SnapshotPath     string
	ControlsDir      string
	ChainsDir        string
	SLAFile          string
	TeamManifestPath string
	Title            string
	Period           string
	Now              time.Time
}

// Builder assembles the full executive report by orchestrating the
// load / score / aggregate steps. cmd/report is a thin wrapper that
// builds Deps from compose, calls Build, and renders the result.
type Builder struct {
	Deps BuilderDeps
}

// Build runs the full report pipeline:
//
//  1. Load history assessments (sorted ascending by Run.Now).
//  2. Load chain definitions for ATT&CK stages.
//  3. Load the snapshot to count assets.
//  4. Compute the posture score and 30-day trajectory delta.
//  5. Build the SLA section if SLAFile is set.
//  6. Aggregate top findings, chains, ATT&CK coverage, teams.
//
// Errors from required inputs (history, chains, snapshot) are fatal;
// optional inputs (SLA, teams) only error when the operator passed an
// explicit path that fails to load.
func (b *Builder) Build(ctx context.Context, in BuilderInput) (*Report, error) {
	// in.Now must be supplied by the caller — Builder is in the app
	// layer and the architecture rules forbid wall-clock reads here.
	// Empty in.Now is a CLI-side configuration error; surface
	// explicitly so a caller running through Clock-port wiring
	// catches a missing Now() at startup, not in the report.
	if in.Now.IsZero() {
		return nil, errors.New("execreport.Builder: BuilderInput.Now is required (use a Clock port at the cmd boundary)")
	}
	now := in.Now

	assessments, err := loadHistory(ctx, b.Deps.ArtifactLoader, in.HistoryDir)
	if err != nil {
		return nil, err
	}
	if len(assessments) == 0 {
		return nil, fmt.Errorf("no assessments in %s", in.HistoryDir)
	}
	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].Run.Now.Before(assessments[j].Run.Now)
	})
	latest := assessments[len(assessments)-1]

	chains, err := b.Deps.ChainLoader.LoadChains(ctx, in.ChainsDir, capabilities.Builtin())
	if err != nil {
		return nil, fmt.Errorf("loading chains: %w", err)
	}

	if _, snapErr := b.Deps.SnapshotBundleLoader.LoadBundle(ctx, in.SnapshotPath); snapErr != nil {
		return nil, fmt.Errorf("loading snapshots for report: %w", snapErr)
	}

	maxChainWeight := appscore.ChainMaxWeight(chains)
	scoreResult := computeScore(latest, len(chains), maxChainWeight)

	// 30-day trajectory: compare against the assessment closest to
	// (now - 30 days). Empty earlier slot → delta=0; never compare
	// the latest with itself.
	var delta float64
	if earlier, ok := assessmentClosestTo(assessments, now.AddDate(0, 0, -30)); ok {
		earlierScore := computeScore(earlier, len(chains), maxChainWeight)
		delta = scoreResult.Score - earlierScore.Score
	}
	trajectory := TrajectoryStable
	if delta >= 5 {
		trajectory = TrajectoryImproving
	} else if delta <= -5 {
		trajectory = TrajectoryRegressing
	}
	sparkline := buildSparkline(assessments, scoreResult.Score, len(chains), maxChainWeight)

	band, bandDesc := Band(scoreResult.Score)

	period := in.Period
	if period == "" {
		period = now.Format("2006-01")
	}

	fs := countFindings(latest)

	var slaSection *SLASection
	if in.SLAFile != "" {
		cfg, slaErr := b.Deps.SLAProvider.LoadSLAConfig(ctx, "", in.SLAFile)
		if slaErr != nil {
			return nil, fmt.Errorf("load --sla-profile-file %q: %w", in.SLAFile, slaErr)
		}
		slaSection = buildSLASection(latest, cfg)
	}

	topFindings := buildTopFindings(latest, 10)
	chainsSection := buildChainsSection(latest)
	attck := buildATTCKSection(ctx, b.Deps.ControlRepo, in.ControlsDir)

	controlsTotal, err := countControls(ctx, b.Deps.ControlRepo, in.ControlsDir)
	if err != nil {
		return nil, err
	}

	var teamSections []TeamSection
	if in.TeamManifestPath != "" {
		manifest, manifestErr := teams.LoadManifest(in.TeamManifestPath)
		if manifestErr != nil {
			return nil, fmt.Errorf("load --team-manifest %q: %w", in.TeamManifestPath, manifestErr)
		}
		teamSections = buildTeamSections(latest, manifest)
	}

	report := &Report{
		SchemaVersion: "1",
		GeneratedAt:   now.Format(time.RFC3339),
		Title:         in.Title,
		Period:        period,
		Posture: PostureSection{
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
		Catalog: CatalogSection{
			ControlsTotal: controlsTotal,
			ChainsTotal:   len(chains),
		},
	}
	report.ExecutiveSummary = GenerateSummary(report)
	return report, nil
}

func loadHistory(ctx context.Context, loader appcontracts.ArtifactLoader, dir string) ([]*corereport.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	out := make([]*corereport.Assessment, 0, len(entries))
	skipped := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			// Tolerate corrupt rotations; surface counts when no entry
			// survives so the all-skipped case doesn't silently render
			// an empty trend chart.
			skipped++
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 && skipped > 0 {
		return nil, fmt.Errorf("no valid assessments in %s (%d files skipped due to errors)", dir, skipped)
	}
	return out, nil
}

func countControls(ctx context.Context, repo appcontracts.ControlRepository, dir string) (int, error) {
	if dir == "" || repo == nil {
		return 0, nil
	}
	loaded, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return 0, fmt.Errorf("load controls from %q: %w", dir, err)
	}
	return len(loaded), nil
}

func buildSparkline(assessments []*corereport.Assessment, latestScore float64, chainDefs int, maxChainWeight float64) []float64 {
	var sparkline []float64
	step := max(1, len(assessments)/7)
	for i := 0; i < len(assessments); i += step {
		s := computeScore(assessments[i], chainDefs, maxChainWeight)
		sparkline = append(sparkline, s.Score)
	}
	if len(sparkline) > 0 && sparkline[len(sparkline)-1] != latestScore {
		sparkline = append(sparkline, latestScore)
	}
	return sparkline
}

// computeScore evaluates the assessment via the appscore engine.
// Pulled out of cmd/ so report builds and any other library caller
// share one definition of "what's the score for this assessment."
func computeScore(a *corereport.Assessment, chainDefs int, maxChainWeight float64) appscore.Result {
	slaTotal := 0
	slaBreached := 0
	hasSLA := false
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.HasSLA() {
			hasSLA = true
			slaTotal++
			if f.IsAnyBreach() {
				slaBreached++
			}
		}
	}

	var violationWeight float64
	for i := range a.Findings {
		violationWeight += appscore.SeverityWeightFor(a.Findings[i].ControlSeverity)
	}
	failingAssets := make(map[string]struct{}, len(a.Findings))
	for i := range a.Findings {
		failingAssets[string(a.Findings[i].AssetID)] = struct{}{}
	}
	passingChecks := max(a.Summary.TotalAssets-len(failingAssets), 0)
	totalCheckWeight := violationWeight + float64(passingChecks)*2.0

	return appscore.Compute(appscore.Input{
		Findings:         a.Findings,
		ChainFindings:    a.ChainFindings,
		ChainDefs:        chainDefs,
		MaxChainWeight:   maxChainWeight,
		SLABreached:      slaBreached,
		SLATotal:         slaTotal,
		TotalCheckWeight: totalCheckWeight,
		HasSLA:           hasSLA,
		Weights:          appscore.DefaultWeights(),
		GeneratedAt:      a.Run.Now,
	})
}

// assessmentClosestTo returns the assessment closest in time to
// target. Returns (_, false) when there isn't enough history to
// compute a meaningful "earlier" — single-point histories have no
// trend data.
func assessmentClosestTo(assessments []*corereport.Assessment, target time.Time) (*corereport.Assessment, bool) {
	if len(assessments) < 2 {
		return nil, false
	}
	var best *corereport.Assessment
	var bestDelta time.Duration
	for i := range assessments[:len(assessments)-1] {
		a := assessments[i]
		d := a.Run.Now.Sub(target)
		if d < 0 {
			d = -d
		}
		if best == nil || d < bestDelta {
			best = a
			bestDelta = d
		}
	}
	return best, best != nil
}
