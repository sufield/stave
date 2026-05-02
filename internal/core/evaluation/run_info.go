package evaluation

import (
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// FilePath is a typed wrapper for file paths to provide type safety within hash maps.
type FilePath string

func (p FilePath) String() string { return string(p) }

// InputHashes maintains SHA-256 fingerprints of the source observation data.
// This structure is critical for the auditability and reproducibility of an evaluation.
type InputHashes struct {
	// Files maps each sanitized file path to its corresponding SHA-256 hex digest.
	Files map[FilePath]kernel.Digest `json:"files"`
	// Overall is an aggregate digest representing the entire set of input files.
	// It is typically computed from a sorted list of "filename:hash" pairs.
	Overall kernel.Digest `json:"overall"`
}

// RunInfo captures the execution context and configuration of a specific evaluation run.
type RunInfo struct {
	StaveVersion      string          `json:"tool_version"`
	Offline           bool            `json:"offline"`
	Now               time.Time       `json:"now"`
	MaxUnsafeDuration kernel.Duration `json:"sla_threshold"`
	Snapshots         int             `json:"snapshots"`
	InputHashes       *InputHashes    `json:"input_hashes,omitempty"`
	// PolicyFingerprint is a deterministic hash of the exact control set used
	// during the run, ensuring that the evaluation logic itself is auditable.
	PolicyFingerprint kernel.Digest `json:"policy_fingerprint,omitempty"`
	// EvaluatedState records the origin context of the evaluated snapshot:
	// "deployed" (CI/CD), "planned" (IaC plan), or "local" (developer workstation).
	EvaluatedState string `json:"evaluated_state"`
}

// IsValid reports whether the run carries the minimum provenance
// fields the strict-mode loader requires: a non-empty stave_version
// and a non-zero now timestamp. Strict callers (gating, enforcement
// generation) need both to make a trust-boundary decision; either
// alone is insufficient. Centralising the check on the type keeps
// the strict-mode contract definition out of the loader and prevents
// future field probing from drifting away from it.
func (r RunInfo) IsValid() bool {
	return r.StaveVersion != "" && !r.Now.IsZero()
}
