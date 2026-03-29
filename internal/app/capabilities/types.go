package capabilities

import (
	"github.com/sufield/stave/internal/core/kernel"
	staveversion "github.com/sufield/stave/internal/version"
)

// IsSourceTypeSupported checks if a source type is supported.
func IsSourceTypeSupported(sourceType kernel.ObservationSourceType) bool {
	_, ok := capabilitiesRegistry.sourceTypeIndex[sourceType]
	return ok
}

// Capabilities describes what this version of Stave supports.
type Capabilities struct {
	Version       string               `json:"version"`
	Offline       bool                 `json:"offline"`
	Observations  ObservationSupport   `json:"observations"`
	Controls      ControlSupport       `json:"controls"`
	Inputs        InputSupport         `json:"inputs"`
	Packs         []ControlPack        `json:"packs"`
	SecurityAudit SecurityAuditSupport `json:"security_audit"`
}

// ControlPack describes an available control pack.
type ControlPack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// ObservationSupport describes supported observation formats.
type ObservationSupport struct {
	SchemaVersions []string `json:"schema_versions"`
}

// ControlSupport describes supported control formats.
type ControlSupport struct {
	DSLVersions []string `json:"dsl_versions"`
}

// InputSupport describes supported input types.
type InputSupport struct {
	SourceTypes []SourceTypeSupport `json:"source_types"`
}

// SourceTypeSupport describes a supported observation source type.
type SourceTypeSupport struct {
	Type        kernel.ObservationSourceType `json:"type"`
	Description string                       `json:"description"`
}

// SecurityAuditSupport describes the supported security-audit command features.
type SecurityAuditSupport struct {
	Enabled              bool     `json:"enabled"`
	Formats              []string `json:"formats"`
	SBOMFormats          []string `json:"sbom_formats"`
	VulnerabilitySources []string `json:"vuln_sources"`
	FailOnLevels         []string `json:"fail_on_levels"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
}

// GetCapabilities returns the capabilities of this Stave version.
func GetCapabilities(version string) Capabilities {
	if version == "" {
		version = staveversion.String
	}

	return Capabilities{
		Version:       version,
		Offline:       true,
		Observations:  capabilitiesRegistry.observationSupport(),
		Controls:      capabilitiesRegistry.controlSupport(),
		Inputs:        capabilitiesRegistry.inputSupport(),
		Packs:         capabilitiesRegistry.packsWithVersion(version),
		SecurityAudit: capabilitiesRegistry.securityAuditSupport(),
	}
}
