package capabilities

import (
	"slices"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/securityaudit"
)

// featureManifest holds pre-sorted, immutable data describing the tool's
// supported security frameworks and cloud connectors.
type featureManifest struct {
	inventorySchemas   []string
	policySchemas      []string
	connectors         []ConnectorSupport
	connectorIndex     map[kernel.ObservationSourceType]struct{}
	policyLibrary      []ControlPack
	complianceFeatures ComplianceSupport
}

func (m *featureManifest) inventorySupport() InventorySupport {
	return InventorySupport{Schemas: m.inventorySchemas}
}

func (m *featureManifest) policySupport() PolicySupport {
	return PolicySupport{Schemas: m.policySchemas}
}

func (m *featureManifest) ingressSupport() IngressSupport {
	return IngressSupport{Connectors: m.connectors}
}

func (m *featureManifest) libraryWithVersion(version string) []ControlPack {
	result := slices.Clone(m.policyLibrary)
	for i := range result {
		result[i].Version = version
	}
	return result
}

func (m *featureManifest) complianceSupport() ComplianceSupport {
	return ComplianceSupport{
		Enabled:        m.complianceFeatures.Enabled,
		ReportFormats:  slices.Clone(m.complianceFeatures.ReportFormats),
		SBOMFormats:    slices.Clone(m.complianceFeatures.SBOMFormats),
		VulnSources:    slices.Clone(m.complianceFeatures.VulnSources),
		FailOnLevels:   slices.Clone(m.complianceFeatures.FailOnLevels),
		Frameworks:     slices.Clone(m.complianceFeatures.Frameworks),
	}
}

// Manifest is the global feature manifest for this version of Stave.
var Manifest = newFeatureManifest()

func newFeatureManifest() *featureManifest {
	inventorySchemas := []string{string(kernel.SchemaObservation)}
	slices.Sort(inventorySchemas)

	policySchemas := []string{string(kernel.SchemaControl)}
	slices.Sort(policySchemas)

	connectors := []ConnectorSupport{
		{
			Type:        kernel.SourceTypeAWSS3Snapshot,
			Description: "AWS S3 Resource State (JSON Snapshots)",
		},
	}

	connectorIndex := make(map[kernel.ObservationSourceType]struct{}, len(connectors))
	for _, c := range connectors {
		connectorIndex[c.Type] = struct{}{}
	}

	packReg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		panic("capabilities: failed to load embedded policy library: " + err.Error())
	}
	discovered := packReg.ListPacks()
	library := make([]ControlPack, len(discovered))
	for i, p := range discovered {
		library[i] = ControlPack{
			Name:        p.Name,
			Description: p.Description,
		}
	}

	complianceFeatures := ComplianceSupport{
		Enabled:       true,
		ReportFormats: securityaudit.AllReportFormats(),
		SBOMFormats:   evidence.AllSBOMFormats(),
		VulnSources:   evidence.AllVulnSources(),
		FailOnLevels:  []string{"critical", "high", "medium", "low", "none"},
		Frameworks:    compliance.FrameworkStrings(compliance.SupportedFrameworks()),
	}

	return &featureManifest{
		inventorySchemas:   inventorySchemas,
		policySchemas:      policySchemas,
		connectors:         connectors,
		connectorIndex:     connectorIndex,
		policyLibrary:      library,
		complianceFeatures: complianceFeatures,
	}
}
