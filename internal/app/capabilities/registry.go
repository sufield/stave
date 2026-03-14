package capabilities

import (
	"slices"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	terraformPlanMinVersion = "1.5.0"
	terraformPlanFormat     = "terraform show -json"

	s3PackName = "s3"
	s3PackPath = "controls/s3"
)

// registry holds pre-sorted, immutable capabilities data.
type registry struct {
	observationSchemaVersions []string
	controlDSLVersions        []string
	sourceTypes               []SourceTypeSupport
	sourceTypeIndex           map[kernel.ObservationSourceType]struct{}
	packs                     []ControlPack
	securityAudit             SecurityAuditSupport
}

func (r *registry) observationSupport() ObservationSupport {
	return ObservationSupport{SchemaVersions: r.observationSchemaVersions}
}

func (r *registry) controlSupport() ControlSupport {
	return ControlSupport{DSLVersions: r.controlDSLVersions}
}

func (r *registry) inputSupport() InputSupport {
	return InputSupport{SourceTypes: r.sourceTypes}
}

func (r *registry) packsWithVersion(version string) []ControlPack {
	result := slices.Clone(r.packs)
	for i := range result {
		result[i].Version = version
	}
	return result
}

func (r *registry) securityAuditSupport() SecurityAuditSupport {
	return SecurityAuditSupport{
		Enabled:              r.securityAudit.Enabled,
		Formats:              slices.Clone(r.securityAudit.Formats),
		SBOMFormats:          slices.Clone(r.securityAudit.SBOMFormats),
		VulnerabilitySources: slices.Clone(r.securityAudit.VulnerabilitySources),
		FailOnLevels:         slices.Clone(r.securityAudit.FailOnLevels),
		ComplianceFrameworks: slices.Clone(r.securityAudit.ComplianceFrameworks),
	}
}

var capabilitiesRegistry = newRegistry()

func newRegistry() *registry {
	schemaVersions := []string{string(kernel.SchemaObservation)}
	slices.Sort(schemaVersions)

	dslVersions := []string{string(kernel.SchemaControl)}
	slices.Sort(dslVersions)

	sourceTypes := []SourceTypeSupport{
		{
			Type:           kernel.SourceTypeTerraformPlanJSON,
			Description:    "Terraform plan JSON output",
			ToolMinVersion: terraformPlanMinVersion,
			PlanFormat:     terraformPlanFormat,
		},
		{
			Type:        kernel.SourceTypeAWSS3Snapshot,
			Description: "S3 snapshot JSON observations",
		},
	}

	sourceTypeIndex := make(map[kernel.ObservationSourceType]struct{}, len(sourceTypes))
	for _, st := range sourceTypes {
		sourceTypeIndex[st.Type] = struct{}{}
	}

	packs := []ControlPack{
		{Name: s3PackName, Path: s3PackPath},
	}

	securityAudit := SecurityAuditSupport{
		Enabled: true,
		Formats: []string{
			"json",
			"markdown",
			"sarif",
		},
		SBOMFormats: []string{
			"spdx",
			"cyclonedx",
		},
		VulnerabilitySources: []string{
			"hybrid",
			"local",
			"ci",
		},
		FailOnLevels: []string{
			"CRITICAL",
			"HIGH",
			"MEDIUM",
			"LOW",
			"NONE",
		},
		ComplianceFrameworks: compliance.FrameworkStrings(compliance.SupportedFrameworks()),
	}

	return &registry{
		observationSchemaVersions: schemaVersions,
		controlDSLVersions:        dslVersions,
		sourceTypes:               sourceTypes,
		sourceTypeIndex:           sourceTypeIndex,
		packs:                     packs,
		securityAudit:             securityAudit,
	}
}
