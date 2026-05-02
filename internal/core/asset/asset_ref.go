package asset

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/kernel"
)

// AssetRef bundles the {ID, Type, Vendor} triple that uniquely
// identifies a domain entity at the evaluation boundary. The triple
// appears across Finding, observation snapshots, and fix-plan
// targets — promoting it to a single value type keeps those shapes
// in lockstep and gives consumers an EvaluableEntity-compatible
// view (GetID/GetType/GetVendor) without reaching into struct
// fields.
//
// Placement note: the spec lists kernel as the home for AssetRef,
// but asset.ID lives in core/asset (a string-newtype with its own
// validator) and the kernel package cannot import core/asset
// without a cycle. AssetRef sits in core/asset alongside the ID
// type so the field types remain consistent. core/kernel still
// owns AssetType / Vendor; AssetRef simply composes them.
type AssetRef struct {
	ID     ID               `json:"id"`
	Type   kernel.AssetType `json:"type"`
	Vendor kernel.Vendor    `json:"vendor"`
}

// NewAssetRef returns a validated AssetRef. ID flows through
// asset.ParseID for whitespace / control-char checks; Type and
// Vendor have no kernel-level validators (they are vocabularies
// extended at runtime), so the validation here only ensures
// non-empty values for those.
func NewAssetRef(id, assetType, vendor string) (AssetRef, error) {
	parsedID, err := ParseID(id)
	if err != nil {
		return AssetRef{}, fmt.Errorf("asset ref id: %w", err)
	}
	if assetType == "" {
		return AssetRef{}, errors.New("asset ref type must not be empty")
	}
	if vendor == "" {
		return AssetRef{}, errors.New("asset ref vendor must not be empty")
	}
	return AssetRef{
		ID:     parsedID,
		Type:   kernel.AssetType(assetType),
		Vendor: kernel.Vendor(vendor),
	}, nil
}

// IsEmpty reports whether the ref carries no identifying information.
// All three fields must be empty for the ref itself to be empty —
// any populated component means a partial ref slipped through.
func (a AssetRef) IsEmpty() bool {
	return a.ID == "" && a.Type == "" && a.Vendor == ""
}

// Equals reports value-equality across all three components. Useful
// for dedup'ing AssetRef-keyed sets without a separate hash key.
func (a AssetRef) Equals(other AssetRef) bool {
	return a.ID == other.ID && a.Type == other.Type && a.Vendor == other.Vendor
}

// GetID satisfies the EvaluableEntity interface.
func (a AssetRef) GetID() ID { return a.ID }

// GetType satisfies the EvaluableEntity interface.
func (a AssetRef) GetType() kernel.AssetType { return a.Type }

// GetVendor satisfies the EvaluableEntity interface.
func (a AssetRef) GetVendor() kernel.Vendor { return a.Vendor }

// Map returns the bare identifying triple as the predicate-evaluable
// shape. AssetRef carries no additional properties — when callers
// need the full property bag they use the originating Asset /
// CloudIdentity. This implementation lets AssetRef satisfy
// EvaluableEntity for code paths that only need identity routing.
func (a AssetRef) Map() map[string]any {
	return map[string]any{
		"id":     a.ID,
		"type":   a.Type,
		"vendor": a.Vendor,
	}
}

// MarshalJSON emits the flat {id, type, vendor} representation so
// existing consumers (Finding wire format, fix-plan targets) keep
// the same JSON shape as the legacy three-field layout.
func (a AssetRef) MarshalJSON() ([]byte, error) {
	type alias AssetRef
	return json.Marshal(alias(a))
}

// UnmarshalJSON parses the flat representation.
func (a *AssetRef) UnmarshalJSON(data []byte) error {
	type alias AssetRef
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*a = AssetRef(v)
	return nil
}

// EvaluableEntity is the contract shared by Asset, CloudIdentity,
// and AssetRef so the evaluation engine and CEL bindings can
// operate on either without per-type plumbing. Map() returns the
// predicate-evaluable property bag (the asset's properties plus
// id/type/vendor); the three Get* accessors expose the identifying
// triple without reaching into struct fields.
//
// Asset.Map and CloudIdentity.Map already produce the right shape;
// the Get* methods are added on those types so they satisfy the
// interface without modification to the wire format.
type EvaluableEntity interface {
	GetID() ID
	GetType() kernel.AssetType
	GetVendor() kernel.Vendor
	Map() map[string]any
}

// GetID returns the asset's identifier.
func (r Asset) GetID() ID { return r.ID }

// GetType returns the asset's type.
func (r Asset) GetType() kernel.AssetType { return r.Type }

// GetVendor returns the asset's vendor.
func (r Asset) GetVendor() kernel.Vendor { return r.Vendor }

// GetID returns the identity's identifier.
func (id CloudIdentity) GetID() ID { return id.ID }

// GetType returns the identity's type.
func (id CloudIdentity) GetType() kernel.AssetType { return id.Type }

// GetVendor returns the identity's vendor.
func (id CloudIdentity) GetVendor() kernel.Vendor { return id.Vendor }

// Compile-time guards: any drift in Asset / CloudIdentity / AssetRef
// shapes that breaks the EvaluableEntity contract surfaces here at
// build time.
var (
	_ EvaluableEntity = Asset{}
	_ EvaluableEntity = CloudIdentity{}
	_ EvaluableEntity = AssetRef{}
)
