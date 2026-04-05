package evaluation

import "github.com/sufield/stave/internal/core/kernel"

// Metadata holds typed provenance for an evaluation run: how controls were
// selected, where they came from, and the state of the source repository.
type Metadata struct {
	ContextName   string            `json:"context_name"`
	ControlSource ControlSourceInfo `json:"control_source"`
	Git           *GitInfo          `json:"git,omitempty"`
	ResolvedPaths ResolvedPaths     `json:"resolved_paths"`
}

// ControlSourceMode identifies how controls were selected for evaluation.
type ControlSourceMode string

// ControlSourceDir and related constants.
const (
	// ControlSourceDir constants.
	ControlSourceDir   ControlSourceMode = "dir"
	ControlSourcePacks ControlSourceMode = "packs"
)

// ControlSourceInfo records which controls were loaded and from where.
type ControlSourceInfo struct {
	Source             ControlSourceMode  `json:"source"`
	EnabledPacks       []kernel.PackName  `json:"enabled_packs,omitempty"`
	ResolvedControlIDs []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	RegistryVersion    string             `json:"registry_version,omitempty"`
	RegistryHash       kernel.Digest      `json:"registry_hash,omitempty"`
}

// GitInfo captures git repository state at evaluation time.
type GitInfo struct {
	RepoRoot  FilePath   `json:"repo_root,omitempty"`
	Head      string     `json:"head,omitempty"`
	Dirty     bool       `json:"dirty"`
	DirtyList []FilePath `json:"dirty_list,omitempty"`
}

// ResolvedPaths records the absolute paths used for controls and observations.
type ResolvedPaths struct {
	Controls     string `json:"controls"`
	Observations string `json:"observations"`
}
