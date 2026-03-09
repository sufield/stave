package evaluation

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// FilePath is a typed wrapper for file path strings used in input hash maps.
type FilePath string

func (p FilePath) String() string { return string(p) }

// InputHashes contains SHA-256 hashes of input observation files for auditability.
type InputHashes struct {
	// Files maps each file path to its SHA-256 hex digest.
	Files map[FilePath]kernel.Digest `json:"files"`
	// Overall is the SHA-256 hex digest of the canonical "filename=hash\n" string
	// built from Files sorted lexicographically by filename.
	Overall kernel.Digest `json:"overall"`
}

// Sanitized returns a copy with file path keys shortened to basenames.
func (h *InputHashes) Sanitized(r kernel.PathSanitizer) *InputHashes {
	if h == nil {
		return nil
	}
	out := &InputHashes{
		Overall: h.Overall,
		Files:   make(map[FilePath]kernel.Digest, len(h.Files)),
	}
	for k, v := range h.Files {
		out.Files[FilePath(r.Path(string(k)))] = v
	}
	return out
}

// RunInfo contains metadata about the evaluation run.
type RunInfo struct {
	ToolVersion string          `json:"tool_version"`
	Offline     bool            `json:"offline"`
	Now         time.Time       `json:"now"`
	MaxUnsafe   kernel.Duration `json:"max_unsafe"`
	Snapshots   int             `json:"snapshots"`
	InputHashes *InputHashes    `json:"input_hashes,omitempty"`
	// PackHash is the SHA-256 hex digest of the evaluated control set,
	// enabling auditability of which controls were active during evaluation.
	PackHash kernel.Digest `json:"pack_hash,omitempty"`
}
