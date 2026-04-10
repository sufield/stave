package capabilities

import (
	"github.com/sufield/stave/internal/core/kernel"
	staveversion "github.com/sufield/stave/internal/version"
)

// IsConnectorSupported verifies if a specific cloud resource source has
// an active connector in this version of the tool.
func IsConnectorSupported(sourceType kernel.ObservationSourceType) bool {
	_, ok := Manifest.connectorIndex[sourceType]
	return ok
}

// AuditCapabilities describes the security frameworks, cloud connectors,
// and policy versions supported by this build of Stave.
type AuditCapabilities struct {
	Version            string             `json:"version"`
	Offline            bool               `json:"offline"`
	ObservationSupport ObservationSupport `json:"observation_support"`
	PolicySupport      PolicySupport      `json:"policy_support"`
	DataIngress        DataIngress        `json:"data_ingress"`
	PolicyLibrary      []PolicyPack       `json:"policy_library"`
	ComplianceSupport  ComplianceSupport  `json:"compliance_support"`
}

// PolicyPack describes a curated collection of pre-defined security controls.
type PolicyPack struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// ObservationSupport defines the supported observation snapshot formats.
type ObservationSupport struct {
	Schemas []string `json:"schemas"`
}

// PolicySupport defines the supported security policy (DSL) versions.
type PolicySupport struct {
	Schemas []string `json:"schemas"`
}

// DataIngress describes the available cloud connectors for importing resource states.
type DataIngress struct {
	Connectors []ConnectorSupport `json:"connectors"`
}

// ConnectorSupport describes a specific cloud provider integration.
type ConnectorSupport struct {
	Type        kernel.ObservationSourceType `json:"type"`
	Description string                       `json:"description"`
}

// ComplianceSupport describes the supported security audit frameworks and reporting.
type ComplianceSupport struct {
	Enabled            bool     `json:"enabled"`
	ReportFormats      []string `json:"report_formats"`
	SBOMFormats        []string `json:"sbom_formats"`
	VulnSources        []string `json:"vuln_sources"`
	SLAThresholds      []string `json:"sla_thresholds"`
	SecurityFrameworks []string `json:"security_frameworks"`
}

// Summarize returns the full audit capability matrix for the current tool version.
func Summarize(version string) AuditCapabilities {
	if version == "" {
		version = staveversion.String
	}

	return AuditCapabilities{
		Version:            version,
		Offline:            true,
		ObservationSupport: Manifest.observationSupport(),
		PolicySupport:      Manifest.policySupport(),
		DataIngress:        Manifest.ingressSupport(),
		PolicyLibrary:      Manifest.libraryWithVersion(version),
		ComplianceSupport:  Manifest.complianceSupport(),
	}
}
