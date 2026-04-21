package stave

import "time"

// Config selects the inputs and evaluation parameters for [Apply].
// Zero values carry useful defaults; only SnapshotsDir is required.
//
// The fields correspond to the CLI flags that affect evaluation
// semantics. Flags that shape rendering or reporting (--format,
// --trace-path, --team-manifest, SLA overlays, SARIF baselines,
// etc.) are not in Config — the library returns typed values and
// leaves those concerns to the caller.
type Config struct {
	// SnapshotsDir is the directory containing observation
	// snapshots (obs.v0.1 JSON files). Maps to the CLI's
	// --observations flag. Required.
	SnapshotsDir string

	// ControlsDir is the directory containing control definitions
	// (ctrl.v1 YAML files). Empty uses the embedded builtin
	// catalog. Maps to the CLI's --controls flag.
	ControlsDir string

	// MaxUnsafe is the maximum duration an asset may remain in an
	// unsafe state before findings are emitted. Zero defers to the
	// engine default. Maps to --max-unsafe.
	MaxUnsafe time.Duration

	// Now overrides the evaluator's current time, which is used
	// for duration-based controls and timestamps in the output.
	// Zero uses the real current time. Maps to --now.
	Now time.Time

	// AllowUnknownInput permits observations whose
	// generated_by.source_type is missing or not in Stave's
	// supported-connector registry. Default (false) rejects such
	// observations with a clear error. Set true when feeding
	// observations from tools that don't annotate with Stave's
	// expected metadata — common when adopting Stave alongside
	// existing collection pipelines. Maps to the CLI's
	// --allow-unknown-input flag.
	AllowUnknownInput bool

	// ChainsDir is the directory containing chain definition YAML
	// files. Chains declare compound-risk patterns — sets of
	// co-failing controls that together represent an attack path.
	// When a chain's escalation threshold is met, the engine emits a
	// ChainFinding on the Assessment and annotates each contributing
	// Finding's ChainMembership.
	//
	// Empty (default) skips chain detection. The CLI auto-discovers
	// chains from the project-root "chains/" directory; the library
	// requires an explicit path for now. A future iteration may add
	// embedded-chain auto-loading to parallel the ControlsDir empty
	// behavior.
	ChainsDir string
}
