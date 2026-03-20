package evaluation

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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

// Sanitized returns a deep copy of the hashes with path keys masked or shortened
// using the provided sanitizer.
func (h *InputHashes) Sanitized(s kernel.PathSanitizer) *InputHashes {
	if h == nil {
		return nil
	}

	sanitizedFiles := make(map[FilePath]kernel.Digest, len(h.Files))
	for path, digest := range h.Files {
		sanitizedFiles[FilePath(s.Path(string(path)))] = digest
	}

	return &InputHashes{
		Files:   sanitizedFiles,
		Overall: h.Overall,
	}
}

// RunInfo captures the execution context and configuration of a specific evaluation run.
type RunInfo struct {
	ToolVersion string          `json:"tool_version"`
	Offline     bool            `json:"offline"`
	Now         time.Time       `json:"now"`
	MaxUnsafe   kernel.Duration `json:"max_unsafe"`
	Snapshots   int             `json:"snapshots"`
	InputHashes *InputHashes    `json:"input_hashes,omitempty"`
	// PackHash is a fingerprint of the exact control set used during the run,
	// ensuring that the evaluation logic itself is auditable.
	PackHash kernel.Digest `json:"pack_hash,omitempty"`
}
