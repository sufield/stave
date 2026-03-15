package kernel

// OutputKind identifies the schema type of a structured output document.
// This value is used by consumers to determine how to parse the JSON payload.
type OutputKind string

func (k OutputKind) String() string { return string(k) }

const (
	// --- Reporting Kinds ---
	KindRemediationReport OutputKind = "remediation_report"

	// --- Baseline & Compliance Kinds ---
	KindBaseline      OutputKind = "baseline"
	KindBaselineCheck OutputKind = "baseline_check"
	KindEnforcement   OutputKind = "enforcement"
	KindGateCheck     OutputKind = "gate_check"

	// --- Observation & State Kinds ---
	KindObservationDelta OutputKind = "observation_delta"
	KindSnapshotArchive  OutputKind = "snapshot_archive"
	KindSnapshotPlan     OutputKind = "snapshot_plan"
	KindSnapshotPrune    OutputKind = "snapshot_prune"
	KindSnapshotQuality  OutputKind = "snapshot_quality"

	// --- Continuous Integration Kinds ---
	KindCIDiff OutputKind = "ci_diff"
)

// validOutputKinds provides a fast lookup for validation.
var validOutputKinds = map[OutputKind]struct{}{
	KindBaseline:          {},
	KindBaselineCheck:     {},
	KindCIDiff:      {},
	KindEnforcement: {},
	KindGateCheck:         {},
	KindObservationDelta:  {},
	KindRemediationReport: {},
	KindSnapshotArchive:   {},
	KindSnapshotPlan:      {},
	KindSnapshotPrune:     {},
	KindSnapshotQuality:   {},
}

// IsValid reports whether the kind is a recognized output document type.
func (k OutputKind) IsValid() bool {
	_, ok := validOutputKinds[k]
	return ok
}
