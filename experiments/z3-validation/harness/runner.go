package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// RunConfig configures one experiment run.
type RunConfig struct {
	Service     ServiceExperiment
	StaveBinary string
	// ControlsDir, when non-empty, is passed to `stave apply
	// --controls`. When empty, Stave's apply path looks for
	// `./controls` relative to the harness's working directory,
	// which is unlikely to exist; per-service Makefile targets
	// supply the absolute repo path.
	ControlsDir string
	FixtureDirs []string
	OutputDir   string
}

// Run executes the experiment for one service against every
// fixture directory in cfg.FixtureDirs, builds the
// [AgreementReport], and writes it to cfg.OutputDir/summary.json.
//
// CEL is the oracle: every fixture is evaluated by Stave's binary
// (via subprocess) before the Z3 model runs. The Z3 model never
// alters the CEL findings; the comparator joins the two.
func Run(ctx context.Context, cfg RunConfig) (*AgreementReport, error) {
	if cfg.Service == nil {
		return nil, fmt.Errorf("harness: Service is required")
	}
	if cfg.StaveBinary == "" {
		return nil, fmt.Errorf("harness: StaveBinary is required")
	}
	if cfg.OutputDir == "" {
		return nil, fmt.Errorf("harness: OutputDir is required")
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("harness: mkdir %s: %w", cfg.OutputDir, err)
	}

	mapping := cfg.Service.ControlMapping()
	report := &AgreementReport{
		Service:        cfg.Service.Name(),
		ExperimentDate: time.Now().UTC(),
		FixtureCount:   len(cfg.FixtureDirs),
		ModelCoverage:  cfg.Service.ModelCoverage(),
	}
	celControls, z3Queries := cfg.Service.CollapseRatio()
	report.CELControlsCount = celControls
	report.Z3QueriesCount = z3Queries
	report.CollapseRatio = fmt.Sprintf("%d CEL controls → %d Z3 queries", celControls, z3Queries)

	for _, fixture := range cfg.FixtureDirs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		celFindings, err := runStaveApply(ctx, cfg.StaveBinary, cfg.ControlsDir, fixture)
		if err != nil {
			// Some test fixtures intentionally carry malformed
			// observations (UNSUPPORTED_SCHEMA_VERSION,
			// truncated payloads, etc.) to exercise Stave's
			// rejection paths. Skipping them keeps the harness
			// resilient against the test-corpus shape; the
			// skipped fixture is recorded on the report so the
			// operator sees the count.
			report.SkippedFixtures = append(report.SkippedFixtures, SkippedFixture{
				Path:   fixture,
				Reason: "stave_apply_error",
				Error:  err.Error(),
			})
			continue
		}
		z3Findings, z3Err := cfg.Service.RunZ3(ctx, fixture)
		if z3Err != nil {
			report.SkippedFixtures = append(report.SkippedFixtures, SkippedFixture{
				Path:   fixture,
				Reason: "z3_model_error",
				Error:  z3Err.Error(),
			})
			continue
		}
		comps := Compare(celFindings, z3Findings, mapping, fixture)
		report.Comparisons = append(report.Comparisons, comps...)
	}

	report.TotalChecks = len(report.Comparisons)
	for _, c := range report.Comparisons {
		switch c.Result {
		case AgreeFail, AgreePass:
			report.Agreements++
		case Z3Only:
			report.Z3Only++
		case CELOnly:
			report.CELOnly++
		}
	}
	if report.TotalChecks > 0 {
		report.AgreementRate = float64(report.Agreements) / float64(report.TotalChecks)
	}

	if err := writeReports(cfg.OutputDir, report); err != nil {
		return nil, fmt.Errorf("write report: %w", err)
	}
	return report, nil
}

// runStaveApply invokes the Stave CLI as a subprocess and parses
// its JSON output. The JSON shape carries findings under a top-
// level "findings" array; the harness reads only (control_id,
// asset_id, verdict-by-presence) — every emitted finding is
// treated as a FAIL since Stave only emits findings for failing
// (control, asset) pairs.
func runStaveApply(ctx context.Context, binary, controlsDir, observationsDir string) ([]CELFinding, error) {
	args := []string{
		"apply",
		"--observations", filepath.Join(observationsDir, "observations"),
		"--format", "json",
		"--allow-unknown-input",
	}
	if controlsDir != "" {
		args = append(args, "--controls", controlsDir)
	}
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // binary path is operator-supplied

	// Capture stdout (the JSON payload) and stderr (warnings,
	// error trailers) separately. Stave returns:
	//   exit 0 — clean run, no findings.
	//   exit 3 — findings present, JSON on stdout.
	//   anything else — fatal input / internal error; surface stderr.
	stdout, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("stave apply: %w", err)
		}
		if exitErr.ExitCode() != 3 {
			return nil, fmt.Errorf("stave apply exit %d: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
		// Exit 3: findings on stdout, fatal-style summary on stderr.
		// stdout was captured by .Output() before the exit error fired.
	}
	// Subprocess-boundary contract (bug-1 class): exit 0 (clean) or
	// 3 (findings) MUST carry the JSON document on stdout. Empty
	// stdout under either exit is a contract violation by stave
	// apply — surface it explicitly so the harness records an
	// upstream regression instead of letting parseStaveFindings
	// return nil findings and quietly mark the fixture "agreed."
	if len(stdout) == 0 {
		return nil, errors.New("stave apply exited cleanly but produced no output (expected out.v0.1 JSON)")
	}
	return parseStaveFindings(stdout)
}

// parseStaveFindings extracts the (control_id, asset_id) tuples
// from a Stave apply JSON document. Schema: top-level "findings"
// array, each element with "control_id" and "asset_id" string
// fields. The harness intentionally does not parse the richer
// finding shape.
func parseStaveFindings(raw []byte) ([]CELFinding, error) {
	var doc struct {
		Findings []struct {
			ControlID string `json:"control_id"`
			AssetID   string `json:"asset_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse stave json: %w", err)
	}
	out := make([]CELFinding, len(doc.Findings))
	for i, f := range doc.Findings {
		out[i] = CELFinding{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
			Verdict:   "FAIL",
		}
	}
	return out, nil
}

// writeReports persists the report and its disagreement subsets
// to outputDir as summary.json, z3_only.json, cel_only.json, and
// agreement.json. Subset files are convenience views.
func writeReports(outputDir string, report *AgreementReport) error {
	if err := writeJSON(filepath.Join(outputDir, "summary.json"), report); err != nil {
		return err
	}
	z3Only := filterByResult(report.Comparisons, Z3Only)
	celOnly := filterByResult(report.Comparisons, CELOnly)
	agree := append(filterByResult(report.Comparisons, AgreeFail), filterByResult(report.Comparisons, AgreePass)...)
	if err := writeJSON(filepath.Join(outputDir, "z3_only.json"), z3Only); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outputDir, "cel_only.json"), celOnly); err != nil {
		return err
	}
	return writeJSON(filepath.Join(outputDir, "agreement.json"), agree)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path) //nolint:gosec // path under harness-owned outputDir
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func filterByResult(in []FindingComparison, result ComparisonResult) []FindingComparison {
	out := make([]FindingComparison, 0, len(in))
	for _, c := range in {
		if c.Result == result {
			out = append(out, c)
		}
	}
	return out
}

// DiscoverFixtures returns observation directories under root
// matching glob "*/observations". Caller-supplied filter narrows
// the result to fixtures relevant to a service. Sorted for
// deterministic iteration.
func DiscoverFixtures(root string, filter func(string) bool) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if filepath.Base(path) != "observations" {
			return nil
		}
		fixture := filepath.Dir(path)
		if filter == nil || filter(fixture) {
			out = append(out, fixture)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
