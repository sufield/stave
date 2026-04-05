package evaluation

import (
	"encoding/json"
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// Extensions represents the typed JSON structure for the out.v0.1 extensions block.
// This is the stable external contract — internal Metadata is projected into it.
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

// GitMetadata is the external (JSON-stable) representation of git state.
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
