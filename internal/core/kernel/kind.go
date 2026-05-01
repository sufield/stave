package kernel

// OutputKind identifies the schema type of a structured output document.
// This value is used by consumers to determine how to parse the JSON payload.
type OutputKind string

func (k OutputKind) String() string { return string(k) }

// Output document kind constants.
const (
	// KindRemediationReport identifies a remediation report document.
	KindRemediationReport OutputKind = "remediation_report"

	// KindBaseline identifies a baseline snapshot document.
	KindBaseline OutputKind = "baseline"
	// KindBaselineCheck identifies a baseline check result document.
	KindBaselineCheck OutputKind = "baseline_check"
	// KindEnforcement identifies an enforcement result document.
	KindEnforcement OutputKind = "enforcement"
	// KindGateCheck identifies a gate check result document.
	KindGateCheck OutputKind = "gate_check"

	// KindObservationDelta identifies an observation delta document.
	KindObservationDelta OutputKind = "observation_delta"
	// KindSnapshotArchive identifies a snapshot archive document.
	KindSnapshotArchive OutputKind = "snapshot_archive"
	// KindSnapshotPlan identifies a snapshot plan document.
	KindSnapshotPlan OutputKind = "snapshot_plan"
	// KindSnapshotPrune identifies a snapshot prune result document.
	KindSnapshotPrune OutputKind = "snapshot_prune"
	// KindSnapshotQuality identifies a snapshot quality report document.
	KindSnapshotQuality OutputKind = "snapshot_quality"

	// KindCIDiff identifies a CI diff result document.
	KindCIDiff OutputKind = "ci_diff"
)

// validOutputKinds provides a fast lookup for validation.
var validOutputKinds = NewEnumSet(
	KindBaseline,
	KindBaselineCheck,
	KindCIDiff,
	KindEnforcement,
	KindGateCheck,
	KindObservationDelta,
	KindRemediationReport,
	KindSnapshotArchive,
	KindSnapshotPlan,
	KindSnapshotPrune,
	KindSnapshotQuality,
)

// IsValid reports whether the kind is a recognized output document type.
func (k OutputKind) IsValid() bool {
	return validOutputKinds.Contains(k)
}
