package capabilities

import (
	"slices"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/securityaudit"
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
			Type:        kernel.SourceTypeAWSS3Snapshot,
			Description: "S3 snapshot JSON observations",
		},
	}

	sourceTypeIndex := make(map[kernel.ObservationSourceType]struct{}, len(sourceTypes))
	for _, st := range sourceTypes {
		sourceTypeIndex[st.Type] = struct{}{}
	}

	// Discover packs from the embedded pack index (single source of truth).
	packReg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		panic("capabilities: load embedded pack registry: " + err.Error())
	}
	discovered := packReg.ListPacks()
	packs := make([]ControlPack, len(discovered))
	for i, p := range discovered {
		packs[i] = ControlPack{
			Name:        p.Name,
			Description: p.Description,
		}
	}

	securityAudit := SecurityAuditSupport{
		Enabled:              true,
		Formats:              securityaudit.AllReportFormats(),
		SBOMFormats:          evidence.AllSBOMFormats(),
		VulnerabilitySources: evidence.AllVulnSources(),
		FailOnLevels:         securityaudit.AllSeverityStrings(),
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
