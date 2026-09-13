package controldef

import "github.com/sufield/stave/internal/core/kernel"

// ControlReader provides read-only access to a control's identity
// and classification metadata. The 50+ packages that only inspect
// controls (renderers, reporters, enrichment passes) can depend on
// this interface instead of the concrete ControlDefinition struct.
type ControlReader interface {
	Metadata() ControlMetadata
	IsEvaluatable() bool
	IsMarker() bool
	IsDeprecated() bool
	AppliesToAssetType(kernel.AssetType) bool
	AttackStage() kernel.AttackStage
	HasCompliance(ComplianceFramework) bool
	IsActionable() bool
	HasDiagnosis() bool
}

var _ ControlReader = (*ControlDefinition)(nil)
