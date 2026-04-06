package capabilities

import (
	"github.com/sufield/stave/internal/core/kernel"
	staveversion "github.com/sufield/stave/internal/version"
)

// IsConnectorSupported checks if a source type has a registered connector.
func IsConnectorSupported(sourceType kernel.ObservationSourceType) bool {
	_, ok := Manifest.connectorIndex[sourceType]
	return ok
}

// Capabilities describes what this version of Stave supports.
type Capabilities struct {
	Version    string            `json:"version"`
	Offline    bool              `json:"offline"`
	Inventory  InventorySupport  `json:"inventory"`
	Policies   PolicySupport     `json:"policies"`
	Ingress    IngressSupport    `json:"ingress"`
	Library    []ControlPack     `json:"policy_library"`
	Compliance ComplianceSupport `json:"compliance"`
}

// ControlPack describes an available control pack.
type ControlPack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// InventorySupport describes supported observation formats.
type InventorySupport struct {
	Schemas []string `json:"schemas"`
}

// PolicySupport describes supported control formats.
type PolicySupport struct {
	Schemas []string `json:"schemas"`
}

// IngressSupport describes supported input types.
type IngressSupport struct {
	Connectors []ConnectorSupport `json:"connectors"`
}

// ConnectorSupport describes a supported observation source type.
type ConnectorSupport struct {
	Type        kernel.ObservationSourceType `json:"type"`
	Description string                       `json:"description"`
}

// ComplianceSupport describes the supported compliance and audit features.
type ComplianceSupport struct {
	Enabled       bool     `json:"enabled"`
	ReportFormats []string `json:"report_formats"`
	SBOMFormats   []string `json:"sbom_formats"`
	VulnSources   []string `json:"vuln_sources"`
	FailOnLevels  []string `json:"fail_on_levels"`
	Frameworks    []string `json:"frameworks"`
}

// GetCapabilities returns the capabilities of this Stave version.
func GetCapabilities(version string) Capabilities {
	if version == "" {
		version = staveversion.String
	}

	return Capabilities{
		Version:    version,
		Offline:    true,
		Inventory:  Manifest.inventorySupport(),
		Policies:   Manifest.policySupport(),
		Ingress:    Manifest.ingressSupport(),
		Library:    Manifest.libraryWithVersion(version),
		Compliance: Manifest.complianceSupport(),
	}
}
