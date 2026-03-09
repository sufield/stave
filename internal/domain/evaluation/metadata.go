package evaluation

import (
	"encoding/json"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Metadata holds typed metadata for an evaluation run.
// It replaces the untyped Extensions map for compile-time safety.
type Metadata struct {
	ContextName   string            `json:"context_name"`
	ControlSource ControlSourceInfo `json:"control_source"`
	Git           *GitInfo          `json:"git,omitempty"`
	ResolvedPaths ResolvedPaths     `json:"resolved_paths"`
}

// ControlSourceMode identifies how controls were selected for evaluation.
type ControlSourceMode string

const (
	// ControlSourceDir means controls were loaded from a filesystem directory.
	ControlSourceDir ControlSourceMode = "dir"
	// ControlSourcePacks means controls were loaded from built-in packs.
	ControlSourcePacks ControlSourceMode = "packs"
)

// ControlSourceInfo describes how controls were selected.
type ControlSourceInfo struct {
	Source             ControlSourceMode `json:"source"`
	EnabledPacks       []string          `json:"enabled_packs,omitempty"`
	ResolvedControlIDs []string          `json:"resolved_control_ids,omitempty"`
	RegistryVersion    string            `json:"registry_version,omitempty"`
	RegistryHash       kernel.Digest     `json:"registry_hash,omitempty"`
}

// GitInfo captures git repository state at evaluation time.
type GitInfo struct {
	RepoRoot  string   `json:"repo_root,omitempty"`
	Head      string   `json:"head,omitempty"`
	Dirty     bool     `json:"dirty"`
	DirtyList []string `json:"dirty_list,omitempty"`
}

// ResolvedPaths records the filesystem paths used for evaluation inputs.
type ResolvedPaths struct {
	Controls     string `json:"controls"`
	Observations string `json:"observations"`
}

// ToMap converts the typed metadata to the flat-key map expected by
// the out.v0.1 JSON wire format (safetyenvelope.Evaluation.Extensions).
func (m Metadata) ToMap() map[string]any {
	// 1. Guard Clause: Precondition for "No Metadata"
	if m.ControlSource.Source == "" {
		return map[string]any{}
	}

	// 2. Marshal/Unmarshal via the Wire Proxy
	wire := m.toWire()
	data, err := json.Marshal(wire)
	if err != nil {
		return map[string]any{}
	}
	var ext map[string]any
	if err := json.Unmarshal(data, &ext); err != nil {
		return map[string]any{}
	}
	if len(ext) == 0 {
		return map[string]any{}
	}
	return ext
}

// Defines the specific JSON shape for the out.v0.1 format
type metadataWire struct {
	SelectedControlsSource string        `json:"selected_controls_source"`
	ContextName            string        `json:"context_name"`
	ResolvedPaths          ResolvedPaths `json:"resolved_paths"`
	EnabledControlPacks    []string      `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs     []string      `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion    string        `json:"pack_registry_version,omitempty"`
	PackRegistryHash       string        `json:"pack_registry_hash,omitempty"`
	GitRepoRoot            string        `json:"git_repo_root,omitempty"`
	GitHeadCommit          string        `json:"git_head_commit,omitempty"`
	GitDirty               *bool         `json:"git_dirty,omitempty"`
	GitPathsDirty          []string      `json:"git_paths_dirty,omitempty"`
}

func (m Metadata) toWire() metadataWire {
	wire := metadataWire{
		SelectedControlsSource: string(m.ControlSource.Source),
		ContextName:            m.ContextName,
		ResolvedPaths:          m.ResolvedPaths,
	}
	// Pack specific metadata
	if m.ControlSource.Source == ControlSourcePacks {
		wire.EnabledControlPacks = append([]string(nil), m.ControlSource.EnabledPacks...)
		wire.ResolvedControlIDs = append([]string(nil), m.ControlSource.ResolvedControlIDs...)
		wire.PackRegistryVersion = m.ControlSource.RegistryVersion
		wire.PackRegistryHash = string(m.ControlSource.RegistryHash)
	}
	// Git metadata with nil safe handling
	if m.Git != nil {
		wire.GitRepoRoot = m.Git.RepoRoot
		wire.GitHeadCommit = m.Git.Head
		dirty := m.Git.Dirty
		wire.GitDirty = &dirty
		if len(m.Git.DirtyList) > 0 {
			wire.GitPathsDirty = append([]string(nil), m.Git.DirtyList...)
		}
	}

	return wire
}

// Extensions holds typed metadata for the out.v0.1 extensions block.
type Extensions struct {
	SelectedSource      string            `json:"selected_controls_source,omitempty"`
	ContextName         string            `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string `json:"resolved_paths,omitempty"`
	EnabledPacks        []string          `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []string          `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string            `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest     `json:"pack_registry_hash,omitempty"`
	Git                 *GitMetadata      `json:"git,omitempty"`
}

// GitMetadata captures git repository state at evaluation time.
type GitMetadata struct {
	RepoRoot string   `json:"repo_root,omitempty"`
	Head     string   `json:"head_commit,omitempty"`
	Dirty    bool     `json:"dirty"`
	Modified []string `json:"modified_paths,omitempty"`
}

// ToExtensions converts domain metadata to the typed extensions struct.
// Returns nil when no metadata is present (empty control source).
func (m Metadata) ToExtensions() *Extensions {
	if m.ControlSource.Source == "" {
		return nil
	}
	ext := &Extensions{
		SelectedSource: string(m.ControlSource.Source),
		ContextName:    m.ContextName,
		ResolvedPaths: map[string]string{
			"controls":     m.ResolvedPaths.Controls,
			"observations": m.ResolvedPaths.Observations,
		},
	}
	if m.ControlSource.Source == ControlSourcePacks {
		ext.EnabledPacks = append([]string(nil), m.ControlSource.EnabledPacks...)
		ext.ResolvedControlIDs = append([]string(nil), m.ControlSource.ResolvedControlIDs...)
		ext.PackRegistryVersion = m.ControlSource.RegistryVersion
		ext.PackRegistryHash = m.ControlSource.RegistryHash
	}
	if m.Git != nil {
		ext.Git = &GitMetadata{
			RepoRoot: m.Git.RepoRoot,
			Head:     m.Git.Head,
			Dirty:    m.Git.Dirty,
		}
		if len(m.Git.DirtyList) > 0 {
			ext.Git.Modified = append([]string(nil), m.Git.DirtyList...)
		}
	}
	return ext
}
