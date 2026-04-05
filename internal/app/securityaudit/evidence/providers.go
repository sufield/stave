package evidence

import (
	"context"
	"time"
)

// BuildInfoProvider collects Go build metadata.
type BuildInfoProvider interface {
	Collect(now time.Time) (BuildInfoSnapshot, error)
}

// SBOMGenerator produces a Software Bill of Materials.
type SBOMGenerator interface {
	Generate(input BuildInfoSnapshot, format SBOMFormat, now time.Time) (SBOMSnapshot, error)
}

// VulnEvidenceProvider resolves vulnerability evidence.
type VulnEvidenceProvider interface {
	Resolve(ctx context.Context, params Params) (VulnerabilitySnapshot, error)
}

// BinaryInspector inspects binary artifacts for integrity and hardening.
type BinaryInspector interface {
	Inspect(params Params, buildInfo BuildInfoSnapshot) (BinaryInspectionSnapshot, error)
}

// PolicyInspector inspects runtime policy compliance.
type PolicyInspector interface {
	Inspect(ctx context.Context, params Params) (PolicyInspectionSnapshot, error)
}

// CrosswalkResolver maps security checks to compliance frameworks.
type CrosswalkResolver interface {
	Resolve(ctx context.Context, params Params, checkIDs []string) (CrosswalkSnapshot, error)
}
