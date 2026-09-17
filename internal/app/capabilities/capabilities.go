package capabilities

import (
	"github.com/sufield/stave/internal/core/kernel"
	staveversion "github.com/sufield/stave/internal/version"
)

// AuditCapabilities describes the security frameworks, cloud connectors,
// and policy versions supported by this build of Stave.
// PolicyPacks is a domain collection of PolicyPack items with querying methods.
type PolicyPacks []PolicyPack

// Len returns the number of policy packs in the collection.
func (pp PolicyPacks) Len() int {
	return len(pp)
}

// ByName returns the policy pack matching the given name, or nil if not found.
func (pp PolicyPacks) ByName(name string) *PolicyPack {
	for i := range pp {
		if pp[i].Name == name {
			return &pp[i]
		}
	}
	return nil
}

// Connectors is a domain collection of ConnectorSupport items with querying methods.
type Connectors []ConnectorSupport

// Len returns the number of connectors in the collection.
func (c Connectors) Len() int {
	return len(c)
}

// ByType returns the connector matching the given observation source type, or nil if not found.
func (c Connectors) ByType(typ kernel.ObservationSourceType) *ConnectorSupport {
	for i := range c {
		if c[i].Type == typ {
			return &c[i]
		}
	}
	return nil
}

// AuditCapabilities describes the security frameworks, cloud connectors,
// and policy versions supported by this build of Stave.
type AuditCapabilities struct {
	Version            string             `json:"version"`
	Offline            bool               `json:"offline"`
	ObservationSupport ObservationSupport `json:"observation_support"`
	PolicySupport      PolicySupport      `json:"policy_support"`
	DataIngress        DataIngress        `json:"data_ingress"`
	PolicyLibrary      PolicyPacks        `json:"policy_library"`
	RiskReasoning      RiskReasoning      `json:"risk_reasoning"`
	ComplianceSupport  ComplianceSupport  `json:"compliance_support"`
}

// RiskReasoning describes the compound risk scoring capabilities.
type RiskReasoning struct {
	Enabled      bool                 `json:"enabled"`
	AttackStages []kernel.AttackStage `json:"attack_stages"`
	ScoringModel string               `json:"scoring_model"`
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
	Connectors Connectors `json:"connectors"`
}

// ConnectorSupport describes a specific cloud provider integration.
type ConnectorSupport struct {
	Type        kernel.ObservationSourceType `json:"type"`
	Description string                       `json:"description"`
}

// ComplianceSupport describes the supported compliance frameworks and reporting.
type ComplianceSupport struct {
	Enabled            bool     `json:"enabled"`
	ReportFormats      []string `json:"report_formats"`
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
		ObservationSupport: Manifest().observationSupport(),
		PolicySupport:      Manifest().policySupport(),
		DataIngress:        Manifest().ingressSupport(),
		PolicyLibrary:      Manifest().libraryWithVersion(version),
		RiskReasoning:      Manifest().riskReasoning(),
		ComplianceSupport:  Manifest().complianceSupport(),
	}
}
