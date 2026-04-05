package evaluation

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

// RemediationPlan describes deterministic, machine-readable remediation guidance.
type RemediationPlan struct {
	ID                 policy.RemediationPlanID `json:"id"`
	ActionsFingerprint string                   `json:"-"`
	Target             RemediationTarget        `json:"target"`
	Preconditions      []string                 `json:"preconditions,omitempty"`
	Actions            []RemediationAction      `json:"actions,omitempty"`
	ExpectedEffect     string                   `json:"expected_effect,omitempty"`
}

// ComputeFingerprint sets ActionsFingerprint to a stable hash of the plan's actions.
func (p *RemediationPlan) ComputeFingerprint(h ports.Digester) {
	if len(p.Actions) == 0 {
		p.ActionsFingerprint = ""
		return
	}
	parts := make([]string, len(p.Actions))
	for i, a := range p.Actions {
		parts[i] = a.CanonicalKey()
	}
	slices.Sort(parts)
	p.ActionsFingerprint = string(h.Digest(parts, '\n'))[:16]
}

// RemediationTarget identifies the asset a remediation plan applies to.
type RemediationTarget struct {
	AssetID   asset.ID         `json:"asset_id"`
	AssetType kernel.AssetType `json:"asset_type"`
}

// RemediationActionType identifies the kind of remediation action (e.g. "set").
type RemediationActionType string

// Canonical remediation action type identifiers.
const (
	ActionSet RemediationActionType = "set"
)

// RemediationAction describes a single remediation step.
type RemediationAction struct {
	ActionType RemediationActionType `json:"action_type"`
	Path       predicate.FieldPath   `json:"path"`
	Value      any                   `json:"value,omitempty"`
}

// CanonicalKey returns a deterministic string representation for hashing.
func (a RemediationAction) CanonicalKey() string {
	val, _ := json.Marshal(a.Value)
	return fmt.Sprintf("%s|%s|%s", a.ActionType, a.Path.String(), val)
}
