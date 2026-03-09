package initcmd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/input/controls/builtin"
	obsjson "github.com/sufield/stave/internal/adapters/input/observations/json"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type quickstartFlagsType struct {
	reportPath string
	nowTime    string
}

type demoFlagsType struct {
	fixtureName string
	reportPath  string
	nowTime     string
}

type detectedSnapshot struct {
	Path   string
	Format string
}

func runQuickstart(cmd *cobra.Command, flags *quickstartFlagsType) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	detected, err := detectSnapshotsForQuickstart(cwd)
	if err != nil {
		return onboardingCommandError(err, "stave quickstart --help")
	}
	out := cmd.OutOrStdout()
	reportPath := fsutil.CleanUserPath(flags.reportPath)
	if strings.TrimSpace(reportPath) == "" {
		return onboardingCommandError(fmt.Errorf("--report cannot be empty"), "stave quickstart --report ./stave-report.json")
	}
	controls, err := loadDemoControls()
	if err != nil {
		return onboardingCommandError(err, "stave quickstart --help")
	}

	snapshots, sourceLabel := loadDetectedQuickstartSnapshots(cwd, detected)

	if len(snapshots) == 0 {
		snapshots, err = loadDemoSnapshots(demoFixtureKnownBad)
		if err != nil {
			return onboardingCommandError(err, "stave demo")
		}
		sourceLabel = "built-in demo fixture"
	}

	result := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:    controls,
		Snapshots:   snapshots,
		MaxUnsafe:   0,
		Clock:       clockadp.FixedClock{Time: snapshots[len(snapshots)-1].CapturedAt},
		ToolVersion: GetVersion(),
	})
	findings := remediation.NewMapper().EnrichFindings(result)
	latest := snapshots[len(snapshots)-1]
	reportNow, err := resolveQuickstartReportTime(latest, flags)
	if err != nil {
		return onboardingCommandError(err, "stave quickstart --now 2026-01-15T00:00:00Z")
	}
	if err := writeDemoReport(demoReportRequest{
		Path:         reportPath,
		Fixture:      "quickstart",
		Snapshot:     latest,
		Result:       result,
		Findings:     findings,
		GeneratedAt:  reportNow,
		Overwrite:    true,
		AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}); err != nil {
		return onboardingCommandError(err, "stave quickstart --report ./stave-report.json")
	}
	san := cmdutil.GetSanitizer(cmd)
	return writeQuickstartSummary(out, san, sourceLabel, findings, latest, reportPath)
}

func loadDetectedQuickstartSnapshots(cwd string, detected []detectedSnapshot) ([]asset.Snapshot, string) {
	for _, d := range detected {
		if !strings.Contains(d.Format, "observation snapshot") {
			continue
		}
		filePath := filepath.Join(cwd, filepath.FromSlash(d.Path))
		snapshots, err := loadQuickstartSnapshotsFromFile(filePath)
		if err != nil || len(snapshots) == 0 {
			continue
		}
		return snapshots, "./" + d.Path
	}
	return nil, ""
}

func resolveQuickstartReportTime(latest asset.Snapshot, flags *quickstartFlagsType) (time.Time, error) {
	reportNow := latest.CapturedAt.UTC()
	if strings.TrimSpace(flags.nowTime) == "" {
		return reportNow, nil
	}
	parsed, err := compose.ResolveNow(flags.nowTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --now %q (use RFC3339: 2026-01-15T00:00:00Z)", flags.nowTime)
	}
	return parsed, nil
}

func detectSnapshotsForQuickstart(base string) ([]detectedSnapshot, error) {
	seen := map[string]bool{}
	results := make([]detectedSnapshot, 0)
	for _, dir := range quickstartCandidateDirs(base) {
		if err := appendDetectedSnapshotsFromDir(base, dir, seen, &results); err != nil {
			return nil, err
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}

func quickstartCandidateDirs(base string) []string {
	return []string{
		filepath.Join(base, "stave.snapshot"),
		filepath.Join(base, "observations"),
		base,
	}
}

func appendDetectedSnapshotsFromDir(base, dir string, seen map[string]bool, results *[]detectedSnapshot) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		snapshot, ok := detectQuickstartSnapshotFromEntry(base, dir, entry, seen)
		if !ok {
			continue
		}
		*results = append(*results, snapshot)
	}
	return nil
}

func detectQuickstartSnapshotFromEntry(base, dir string, entry os.DirEntry, seen map[string]bool) (detectedSnapshot, bool) {
	if entry.IsDir() {
		return detectedSnapshot{}, false
	}
	name := entry.Name()
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		return detectedSnapshot{}, false
	}
	fullPath := filepath.Join(dir, name)
	if seen[fullPath] {
		return detectedSnapshot{}, false
	}
	format, ok := detectSnapshotFormat(fullPath)
	if !ok {
		return detectedSnapshot{}, false
	}
	seen[fullPath] = true
	rel, err := filepath.Rel(base, fullPath)
	if err != nil {
		rel = fullPath
	}
	return detectedSnapshot{
		Path:   filepath.ToSlash(rel),
		Format: format,
	}, true
}

func detectSnapshotFormat(path string) (string, bool) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return "", false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return "", false
	}

	if _, ok := top["captured_at"]; ok {
		if _, ok := top["assets"]; ok {
			return "observation snapshot (obs.v0.1)", true
		}
	}
	if _, ok := top["snapshots"]; ok {
		return "observation snapshot bundle (obs.v0.1)", true
	}
	if _, ok := top["planned_values"]; ok {
		return "terraform plan JSON", true
	}
	if _, ok := top["resource_changes"]; ok {
		return "terraform plan JSON", true
	}
	if strings.EqualFold(filepath.Base(path), "list-buckets.json") {
		return "aws s3 CLI snapshot", true
	}
	return "generic JSON snapshot", true
}

func loadQuickstartSnapshotsFromFile(path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}

	loader, err := compose.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}

	// First try strict single-snapshot loading (schema + semantic validation).
	if single, err := loader.LoadSnapshotFromReader(context.Background(), bytes.NewReader(data), path); err == nil {
		return []asset.Snapshot{single}, nil
	}

	// Then try bundle format and validate each snapshot entry independently.
	var bundle struct {
		SchemaVersion kernel.Schema     `json:"schema_version"`
		Snapshots     []json.RawMessage `json:"snapshots"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	if len(bundle.Snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots found in %s", path)
	}
	snapshots := make([]asset.Snapshot, 0, len(bundle.Snapshots))
	for i, raw := range bundle.Snapshots {
		snap, loadErr := loader.LoadSnapshotFromReader(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%s.snapshots[%d]", path, i))
		if loadErr != nil {
			return nil, loadErr
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots, nil
}

//go:embed fixtures/demo/snapshot-known-bad.json
var demoSnapshotKnownBad []byte

//go:embed fixtures/demo/snapshot-known-good.json
var demoSnapshotKnownGood []byte

const (
	demoFixtureKnownBad  = "known-bad"
	demoFixtureKnownGood = "known-good"
)

func runDemo(cmd *cobra.Command, flags *demoFlagsType) error {
	fixture := strings.TrimSpace(flags.fixtureName)
	snapshots, err := loadDemoSnapshots(fixture)
	if err != nil {
		return onboardingCommandError(err, "stave demo --help")
	}

	controls, err := loadDemoControls()
	if err != nil {
		return onboardingCommandError(err, "stave demo --help")
	}

	lastSnap := snapshots[len(snapshots)-1]
	result := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:    controls,
		Snapshots:   snapshots,
		MaxUnsafe:   0,
		Clock:       clockadp.FixedClock{Time: lastSnap.CapturedAt},
		ToolVersion: GetVersion(),
	})
	findings := remediation.NewMapper().EnrichFindings(result)

	reportNow := lastSnap.CapturedAt.UTC()
	if strings.TrimSpace(flags.nowTime) != "" {
		reportNow, err = compose.ResolveNow(flags.nowTime)
		if err != nil {
			return onboardingCommandError(fmt.Errorf("invalid --now %q (use RFC3339: 2026-01-15T00:00:00Z)", flags.nowTime), "stave demo --now 2026-01-15T00:00:00Z")
		}
	}

	reportPath := fsutil.CleanUserPath(flags.reportPath)
	if strings.TrimSpace(reportPath) == "" {
		return onboardingCommandError(fmt.Errorf("--report cannot be empty"), "stave demo --report ./stave-report.json")
	}

	if err := writeDemoReport(demoReportRequest{
		Path:         reportPath,
		Fixture:      fixture,
		Snapshot:     lastSnap,
		Result:       result,
		Findings:     findings,
		GeneratedAt:  reportNow,
		Overwrite:    true,
		AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}); err != nil {
		return onboardingCommandError(err, "stave demo --report ./stave-report.json")
	}

	return printDemoSummary(cmd.OutOrStdout(), cmdutil.GetSanitizer(cmd), lastSnap, findings, reportPath)
}

func loadDemoSnapshots(name string) ([]asset.Snapshot, error) {
	if name == "" {
		name = demoFixtureKnownBad
	}
	var b []byte
	switch name {
	case demoFixtureKnownBad:
		b = demoSnapshotKnownBad
	case demoFixtureKnownGood:
		b = demoSnapshotKnownGood
	default:
		return nil, fmt.Errorf("unsupported --fixture %q (use: %s, %s)", name, demoFixtureKnownBad, demoFixtureKnownGood)
	}

	snapshots, err := obsjson.ParseBundle(b)
	if err != nil {
		return nil, fmt.Errorf("parse embedded fixture %q: %w", name, err)
	}
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("embedded fixture %q has no snapshots", name)
	}
	return snapshots, nil
}

func loadDemoControls() ([]policy.ControlDefinition, error) {
	all, err := builtin.LoadAll(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load built-in controls: %w", err)
	}
	allow := make(map[string]bool, len(demoFastLaneControlIDs))
	for _, id := range demoFastLaneControlIDs {
		allow[id] = true
	}
	selected := make([]policy.ControlDefinition, 0, len(demoFastLaneControlIDs))
	for _, ctl := range all {
		if allow[string(ctl.ID)] {
			selected = append(selected, ctl)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("demo control set is empty")
	}
	slices.SortFunc(selected, func(a, b policy.ControlDefinition) int {
		return strings.Compare(string(a.ID), string(b.ID))
	})
	return selected, nil
}

type demoReport struct {
	SchemaVersion string             `json:"schema_version"`
	Kind          string             `json:"kind"`
	Fixture       string             `json:"fixture"`
	GeneratedAt   string             `json:"generated_at"`
	Summary       evaluation.Summary `json:"summary"`
	TopFinding    *demoFindingRef    `json:"top_finding,omitempty"`
}

type demoFindingRef struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Evidence  string           `json:"evidence"`
	FixHint   string           `json:"fix_hint"`
}

func writeDemoReport(req demoReportRequest) error {
	report := demoReport{
		SchemaVersion: string(kernel.SchemaDemoReport),
		Kind:          "demo_report",
		Fixture:       req.Fixture,
		GeneratedAt:   req.GeneratedAt.UTC().Format(time.RFC3339),
		Summary:       req.Result.Summary,
	}
	if len(req.Findings) > 0 {
		top := req.Findings[0]
		report.TopFinding = &demoFindingRef{
			ControlID: top.ControlID,
			AssetID:   top.AssetID,
			Evidence:  demoEvidenceLine(req.Snapshot, string(top.AssetID)),
			FixHint:   demoFixHint,
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal demo report: %w", err)
	}

	parent := filepath.Dir(req.Path)
	if parent != "." {
		if err := fsutil.SafeMkdirAll(parent, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: req.AllowSymlink}); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = req.Overwrite
	opts.AllowSymlink = req.AllowSymlink
	if err := fsutil.SafeWriteFile(req.Path, append(data, '\n'), opts); err != nil {
		return fmt.Errorf("write demo report: %w", err)
	}
	return nil
}

func runGenerateControl(cmd *cobra.Command, args []string, outPath string) error {
	name := strings.TrimSpace(args[0])
	if name == "" {
		return fmt.Errorf("control name cannot be empty")
	}
	id := controlIDFromName(name)
	content := strings.ReplaceAll(strings.TrimLeft(templateControlCanonical, "\n"), "CTL.S3.PUBLIC.901", id)
	out := strings.TrimSpace(outPath)
	if out == "" {
		out = filepath.Join("controls", id+".yaml")
	}
	return writeGeneratedFile(out, []byte(content), cmd)
}

func runGenerateObservation(cmd *cobra.Command, args []string, outPath string) error {
	name := strings.TrimSpace(args[0])
	if name == "" {
		return fmt.Errorf("observation name cannot be empty")
	}
	slug := sanitizeSlug(name)
	content := strings.ReplaceAll(strings.TrimLeft(templateObservation, "\n"), "aws:s3:::example-phi-bucket", "asset:"+slug)
	out := strings.TrimSpace(outPath)
	if out == "" {
		out = filepath.Join("observations", slug+".json")
	}
	return writeGeneratedFile(out, []byte(content), cmd)
}

func writeGeneratedFile(path string, content []byte, cmd *cobra.Command) error {
	path = fsutil.CleanUserPath(path)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path cannot be empty")
	}
	force := cmdutil.ForceEnabled(cmd)
	allowSymlink := cmdutil.AllowSymlinkOutEnabled(cmd)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", path)
		}
	}
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700, AllowSymlink: allowSymlink}); err != nil {
		return err
	}
	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = force
	opts.AllowSymlink = allowSymlink
	if err := fsutil.SafeWriteFile(path, content, opts); err != nil {
		return err
	}
	if !cmdutil.QuietEnabled(cmd) {
		fmt.Fprintf(os.Stdout, "Generated %s\n", path)
	}
	return nil
}
