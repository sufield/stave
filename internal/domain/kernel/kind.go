package kernel

// OutputKind identifies the type of structured output document.
// Each constant corresponds to a stable "kind" value written into JSON output.
type OutputKind string

func (k OutputKind) String() string { return string(k) }

// Core output kinds.
const (
	KindBaseline         OutputKind = "baseline"
	KindBaselineCheck    OutputKind = "baseline_check"
	KindCIDiff           OutputKind = "ci_diff"
	KindDemoReport       OutputKind = "demo_report"
	KindEnforcement      OutputKind = "enforcement"
	KindGateCheck        OutputKind = "gate_check"
	KindObservationDelta OutputKind = "observation_delta"
	KindRemediationReport OutputKind = "remediation_report"
	KindSnapshotArchive  OutputKind = "snapshot_archive"
	KindSnapshotPlan     OutputKind = "snapshot_plan"
	KindSnapshotPrune    OutputKind = "snapshot_prune"
	KindSnapshotQuality  OutputKind = "snapshot_quality"
)
