package evaluation

import (
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

	return ext
}
