package evaluation

import (
	"encoding/json"
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// Metadata holds typed metadata for an evaluation run.
// It is the internal domain representation of the evaluation context.
type Metadata struct {
	ContextName   string            `json:"context_name"`
	ControlSource ControlSourceInfo `json:"control_source"`
	Git           *GitInfo          `json:"git,omitempty"`
	ResolvedPaths ResolvedPaths     `json:"resolved_paths"`
}

// ControlSourceMode identifies how controls were selected for evaluation.
type ControlSourceMode string

const (
	ControlSourceDir   ControlSourceMode = "dir"
	ControlSourcePacks ControlSourceMode = "packs"
)

type ControlSourceInfo struct {
	Source             ControlSourceMode  `json:"source"`
	EnabledPacks       []kernel.PackName  `json:"enabled_packs,omitempty"`
	ResolvedControlIDs []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	RegistryVersion    string             `json:"registry_version,omitempty"`
	RegistryHash       kernel.Digest      `json:"registry_hash,omitempty"`
}

type GitInfo struct {
	RepoRoot  FilePath   `json:"repo_root,omitempty"`
	Head      string     `json:"head,omitempty"`
	Dirty     bool       `json:"dirty"`
	DirtyList []FilePath `json:"dirty_list,omitempty"`
}

type ResolvedPaths struct {
	Controls     string `json:"controls"`
	Observations string `json:"observations"`
}

// --- Output Projection (DTOs) ---

// Extensions represents the typed JSON structure for the out.v0.1 extensions block.
type Extensions struct {
	SelectedSource      string             `json:"selected_controls_source,omitempty"`
	ContextName         string             `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string  `json:"resolved_paths,omitempty"`
	EnabledPacks        []kernel.PackName  `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string             `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest      `json:"pack_registry_hash,omitempty"`
	Git                 *GitMetadata       `json:"git,omitempty"`
}

// GitMetadata captures git repository state at evaluation time.
type GitMetadata struct {
	RepoRoot string   `json:"repo_root,omitempty"`
	Head     string   `json:"head_commit,omitempty"`
	Dirty    bool     `json:"dirty"`
	Modified []string `json:"modified_paths,omitempty"`
}

// ToExtensions projects the internal Metadata into the report-friendly Extensions DTO.
// Returns nil if the Metadata is empty (uninitialized source).
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
		ext.EnabledPacks = slices.Clone(m.ControlSource.EnabledPacks)
		ext.ResolvedControlIDs = slices.Clone(m.ControlSource.ResolvedControlIDs)
		ext.PackRegistryVersion = m.ControlSource.RegistryVersion
		ext.PackRegistryHash = m.ControlSource.RegistryHash
	}

	if m.Git != nil {
		modified := make([]string, len(m.Git.DirtyList))
		for i, p := range m.Git.DirtyList {
			modified[i] = string(p)
		}
		ext.Git = &GitMetadata{
			RepoRoot: string(m.Git.RepoRoot),
			Head:     m.Git.Head,
			Dirty:    m.Git.Dirty,
			Modified: modified,
		}
	}

	return ext
}

// ToMap converts the typed metadata into the flattened map required by the
// legacy out.v0.1 JSON wire format.
func (m Metadata) ToMap() map[string]any {
	ext := m.ToExtensions()
	if ext == nil {
		return make(map[string]any)
	}

	data, err := json.Marshal(ext)
	if err != nil {
		return make(map[string]any)
	}

	var flat map[string]any
	if err := json.Unmarshal(data, &flat); err != nil {
		return make(map[string]any)
	}

	return flat
}
