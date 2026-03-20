package asset

import (
	"maps"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// SourceRef points to the source file and line where the asset is defined.
type SourceRef struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Asset represents a single infrastructure component such as an S3 bucket,
// IAM role, or database instance. Properties contain vendor-specific attributes
// that predicates evaluate to determine if the asset is unsafe.
type Asset struct {
	ID         ID               `json:"id"`
	Type       kernel.AssetType `json:"type"`
	Vendor     kernel.Vendor    `json:"vendor"`
	Properties map[string]any   `json:"properties"`
	Source     *SourceRef       `json:"source,omitempty"`
}

// Map returns predicate-evaluable properties including core fields.
// Mirrors CloudIdentity.Map() so the predicate engine sees a consistent
// set of base fields (id, type, vendor) across all evaluated components.
func (r Asset) Map() map[string]any {
	out := make(map[string]any, len(r.Properties)+3)
	out["id"] = r.ID
	out["type"] = r.Type
	out["vendor"] = r.Vendor
	if r.Properties != nil {
		maps.Copy(out, r.Properties)
	}
	return out
}

// IsProvablySafe reports whether the asset's safety_provable property is
// explicitly true. Returns false when the property is missing or false.
func (r Asset) IsProvablySafe() bool {
	provable, ok := r.Properties["safety_provable"].(bool)
	return ok && provable
}

// CloudIdentity represents an IAM identity such as a user, role, or service account.
// Identity attributes are stored in a flexible properties map so predicate evaluation
// can use a unified model across both assets and identities.
type CloudIdentity struct {
	ID         ID               `json:"id"`
	Type       kernel.AssetType `json:"type"` // e.g., "iam_role", "service_account"
	Vendor     kernel.Vendor    `json:"vendor"`
	Properties map[string]any   `json:"properties"`
	Source     *SourceRef       `json:"source,omitempty"`
}

// Map returns predicate-evaluable identity attributes as a flat map.
// Identity core fields are included so predicates can match on "type", "vendor", and "id"
// without reaching into struct fields. Domain types are stored directly to avoid
// per-call String() allocations; the predicate engine handles typed-string comparison.
func (id CloudIdentity) Map() map[string]any {
	out := make(map[string]any, len(id.Properties)+3)
	out["id"] = id.ID
	out["type"] = id.Type
	out["vendor"] = id.Vendor
	if id.Properties != nil {
		maps.Copy(out, id.Properties)
	}
	return out
}
