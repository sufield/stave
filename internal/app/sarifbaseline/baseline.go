// Package sarifbaseline computes SARIF baselineState and suppressions
// by comparing current findings against a baseline assessment. This
// enables GitHub Code Scanning to show only new findings in PR
// annotations while tracking pre-existing violations separately.
package sarifbaseline

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// BaselineState is the SARIF baselineState enum.
type BaselineState string

const (
	StateNew       BaselineState = "new"
	StateUnchanged BaselineState = "unchanged"
	StateAbsent    BaselineState = "absent"
	StateUpdated   BaselineState = "updated"
)

// Suppression represents a SARIF suppression entry for exempted findings.
type Suppression struct {
	Kind          string         `json:"kind"`
	Status        string         `json:"status"`
	Justification string         `json:"justification"`
	Properties    map[string]any `json:"properties,omitempty"`
}

// findingKey uniquely identifies a finding across assessments.
type findingKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// BaselineEntry holds the state of a single finding relative to baseline.
type BaselineEntry struct {
	ControlID     kernel.ControlID `json:"control_id"`
	AssetID       asset.ID         `json:"asset_id"`
	BaselineState BaselineState    `json:"baseline_state"`
	Suppressions  []Suppression    `json:"suppressions,omitempty"`
}

// BaselineFinding holds baseline finding data for comparison.
type BaselineFinding struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
	Severity  policy.Severity
}

// Result holds the baseline comparison output.
type Result struct {
	Entries map[findingKey]BaselineEntry
}

// Compare produces baseline states for current findings relative to
// baseline findings. If baseline is nil, all findings are "new".
func Compare(current, baseline []BaselineFinding) *Result {
	result := &Result{
		Entries: make(map[findingKey]BaselineEntry),
	}

	if len(baseline) == 0 {
		for _, f := range current {
			k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
			result.Entries[k] = BaselineEntry{
				ControlID:     f.ControlID,
				AssetID:       f.AssetID,
				BaselineState: StateNew,
			}
		}
		return result
	}

	// Build baseline index.
	baselineIndex := make(map[findingKey]*BaselineFinding, len(baseline))
	for i := range baseline {
		k := findingKey{ControlID: baseline[i].ControlID, AssetID: baseline[i].AssetID}
		baselineIndex[k] = &baseline[i]
	}

	// Build current index.
	currentIndex := make(map[findingKey]*BaselineFinding, len(current))
	for i := range current {
		k := findingKey{ControlID: current[i].ControlID, AssetID: current[i].AssetID}
		currentIndex[k] = &current[i]
	}

	// Classify current findings.
	for _, f := range current {
		k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
		bf, inBaseline := baselineIndex[k]

		if !inBaseline {
			result.Entries[k] = BaselineEntry{
				ControlID:     f.ControlID,
				AssetID:       f.AssetID,
				BaselineState: StateNew,
			}
			continue
		}

		state := StateUnchanged
		if bf.Severity != f.Severity {
			state = StateUpdated
		}
		result.Entries[k] = BaselineEntry{
			ControlID:     f.ControlID,
			AssetID:       f.AssetID,
			BaselineState: state,
		}
	}

	// Absent: in baseline but not in current.
	for _, f := range baseline {
		k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
		if _, inCurrent := currentIndex[k]; !inCurrent {
			result.Entries[k] = BaselineEntry{
				ControlID:     f.ControlID,
				AssetID:       f.AssetID,
				BaselineState: StateAbsent,
			}
		}
	}

	return result
}

// Lookup returns the baseline state for a specific finding.
func (r *Result) Lookup(ctlID kernel.ControlID, astID asset.ID) BaselineState {
	if r == nil {
		return StateNew
	}
	k := findingKey{ControlID: ctlID, AssetID: astID}
	if e, ok := r.Entries[k]; ok {
		return e.BaselineState
	}
	return StateNew
}

// BuildSuppression creates a SARIF suppression entry for an exempted finding.
func BuildSuppression(approver, reason, expiryDate, exemptionID string) Suppression {
	props := map[string]any{}
	if approver != "" {
		props["approver"] = approver
	}
	if exemptionID != "" {
		props["exemption_id"] = exemptionID
	}
	if expiryDate != "" {
		props["expires_at"] = expiryDate
	}

	return Suppression{
		Kind:          "inSource",
		Status:        "accepted",
		Justification: reason,
		Properties:    props,
	}
}
