package stave

import (
	"github.com/sufield/stave/pkg/stave/internal/forgecmd"
)

// ForgePreview evaluates a control predicate (field/op/value, or a raw
// expression) against a snapshot's matching assets and returns the per-asset
// FAIL/PASS report. All failures stay plain (exit 4). Library entry point
// behind `stave forge preview`.
func ForgePreview(snapshotPath, assetType, field, op, value, predicateExpr string) ([]byte, error) {
	return forgecmd.Preview(snapshotPath, assetType, field, op, value, predicateExpr) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeLivePreview renders the authoring wizard's live-preview block (a
// best-effort FAIL/PASS view of a field/op/value predicate). Library entry
// point behind the `stave forge new` wizard's preview step.
func ForgeLivePreview(snapshotPath, assetType, field, op, value string) ([]byte, error) {
	return forgecmd.LivePreview(snapshotPath, assetType, field, op, value) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgePaths lists the observation property paths (types + presence counts)
// for assets of the given type in a snapshot, filtered by substring. Library
// entry point behind `stave forge paths` (and the wizard's path step).
func ForgePaths(snapshotPath, assetType, filter string) ([]byte, error) {
	return forgecmd.Paths(snapshotPath, assetType, filter) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeSnapshotAssetCount reports the most-recent snapshot's asset count.
// loaded is false when the bundle parsed but holds no snapshots. Library
// helper for the wizard's "Loaded snapshot with N assets" banner.
func ForgeSnapshotAssetCount(path string) (count int, loaded bool, err error) {
	return forgecmd.SnapshotAssetCount(path) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeSnapshotAssetTypes returns the distinct asset types in a snapshot's
// most-recent snapshot. Library helper for the wizard's asset-type step.
func ForgeSnapshotAssetTypes(path string) ([]string, error) {
	return forgecmd.SnapshotAssetTypes(path) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeScaffold generates minimal pass/fail fixture files (extracting only the
// predicate-referenced properties) under outDir and returns the status output.
// Library entry point behind `stave forge scaffold`.
func ForgeScaffold(controlPath, snapshotPath, outDir string) ([]byte, error) {
	return forgecmd.Scaffold(controlPath, snapshotPath, outDir) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeLint runs static analysis over a control YAML file/directory and
// returns the report; a non-nil error gates the run (exit 4) when errors exist
// (or strict + warnings exist) — the report is still rendered. Library entry
// point behind `stave forge lint`.
func ForgeLint(controlPath string, semantic, strict bool) ([]byte, error) {
	return forgecmd.Lint(controlPath, semantic, strict) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeLintWithFormat is ForgeLint with configurable output format ("text" or "json").
func ForgeLintWithFormat(controlPath string, semantic, strict bool, format string) ([]byte, error) {
	return forgecmd.LintWithFormat(controlPath, semantic, strict, format) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeChainLint validates a chain definition and returns the report; a
// non-nil error gates the run (exit 4) when errors exist — the report is still
// rendered. Library entry point behind `stave forge chain lint`.
func ForgeChainLint(chainPath, controlsDir string) ([]byte, error) {
	return forgecmd.ChainLint(chainPath, controlsDir) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeTest evaluates a control against pass/fail fixtures (and optionally a
// snapshot) and returns the assertion report; a non-nil error gates the run
// (exit 4) when any assertion fails — the report is still rendered. Library
// entry point behind `stave forge test`.
func ForgeTest(controlPath, passFixture, failFixture, snapshotPath string, verbose bool) ([]byte, error) {
	return forgecmd.Test(controlPath, passFixture, failFixture, snapshotPath, verbose) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ForgeValidateGenerated finds <controlID>.yaml under outDir and validates it
// (parse + Prepare), returning the status output and a non-nil error when the
// expected control is absent or invalid. Library entry point behind the
// validation step of `stave forge new`.
func ForgeValidateGenerated(controlID, outDir string) ([]byte, error) {
	return forgecmd.ValidateGenerated(controlID, outDir) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}
