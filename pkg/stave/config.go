package stave

import (
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/ports"
)

// ProjectConfigInput holds project configuration that affects
// evaluation. Aliased from internal/app/eval to avoid mirroring
// PackRegistry and BuiltinLoader callbacks. CLI callers populate
// this from stave.yaml before calling Apply.
type ProjectConfigInput = appeval.ProjectConfigInput

// Tracer is the optional logic-trace recorder. When non-nil, the
// engine records every (control, asset) decision step into the
// tracer for later export. The CLI's --trace flag wires this up;
// library callers leave it nil unless they want trace output.
type Tracer = ports.Tracer

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
	// Zero uses the real current time. Maps to --eval-time.
	EvalTime time.Time

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

	// GraphFindingsDir points to pre-computed Soufflé .csv output.
	// When set, graph-based chain findings are appended to the report.
	GraphFindingsDir string

	// ExemptionRules carries asset-level exemptions evaluated
	// before the engine fires. Assets matching any rule are
	// excluded from evaluation entirely and surfaced under
	// Assessment.ExemptedAssets (subject to consumer-visible
	// surface; see Assessment). Nil disables exemption matching.
	ExemptionRules *ExemptionConfig

	// AcknowledgmentRules suppresses findings for control/asset
	// pairs explicitly accepted as residual risk. Acknowledged
	// findings remain in the findings array with status SUPPRESSED.
	AcknowledgmentRules *AcknowledgmentConfig

	// SLAConfig parameterizes SLA breach detection. When non-nil,
	// every finding whose dwell time exceeds the
	// severity-specific deadline is flagged SLABreached on the
	// finding and counted in Assessment.SLABreaches. The
	// escalation factor bumps severity for chronic breaches.
	// Nil disables SLA evaluation. Maps to the CLI's
	// --sla-profile / --sla-profile-file flags after they have
	// been resolved into the canonical config form.
	SLAConfig *SLAConfig

	// IntegrityManifest is the path to the manifest used to
	// verify observation provenance. When set together with
	// IntegrityPublicKey, the observation loader rejects any
	// snapshot whose checksum doesn't match. Empty disables
	// integrity verification. Maps to --integrity-manifest.
	IntegrityManifest string

	// IntegrityPublicKey is the path to the Ed25519 public key
	// authorizing the manifest. Required when IntegrityManifest
	// is set; ignored when manifest is empty. Maps to
	// --integrity-public-key.
	IntegrityPublicKey string

	// ProjectConfig, when non-nil, supplies project-scoped settings
	// that affect evaluation: control-pack selection, exception
	// policies, exclude lists, and an optional builtin-control
	// loader override. CLI callers build this from stave.yaml.
	// Library callers typically leave it nil and rely on the
	// embedded built-in catalog plus explicit Config fields.
	ProjectConfig *ProjectConfigInput

	// Tracer, when non-nil, receives a (control, asset) decision
	// span for every evaluation. CLI callers wire it from --trace
	// so the exported JSON trace can be inspected. Library callers
	// who don't need traces leave it nil and the engine's
	// no-op tracer takes over.
	Tracer Tracer

	// ContextName is the project context label that lands on the
	// assessment's run.context_name field. CLI callers populate from
	// the resolved project context (typically "stave"). Library
	// callers usually leave empty; the field is decorative.
	ContextName string
}
