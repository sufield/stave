// Package narrative assembles guided remediation playbooks from
// structured finding data, control metadata, and chain context.
// No network calls — fully offline, air-gap compatible.
package narrative

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Playbook is the complete narrative output for a single finding.
type Playbook struct {
	FindingID   string            `json:"finding_id"`
	ControlID   kernel.ControlID  `json:"control_id"`
	AssetID     asset.ID          `json:"asset_id"`
	Severity    policy.Severity   `json:"severity"`
	ControlName string            `json:"control_name"`
	Narrative   NarrativeSections `json:"narrative"`
}

// NarrativeSections holds the five narrative sections.
type NarrativeSections struct {
	WhyThisMatters string             `json:"why_this_matters,omitempty"`
	AttackStage    kernel.AttackStage `json:"attack_stage,omitempty"`
	CurrentState   []StateEntry       `json:"current_state,omitempty"`
	Steps          []Step             `json:"steps"`
	ChainContext   *ChainContext      `json:"chain_context,omitempty"`
}

// StateEntry shows a single observed property vs required.
type StateEntry struct {
	PropertyPath   string `json:"property_path"`
	CurrentValue   string `json:"current_value"`
	RequiredValue  string `json:"required_value"`
	HasSafeDefault bool   `json:"has_safe_default"`
}

// ConfidenceLevel classifies step confidence.
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "high"
	ConfidenceMedium ConfidenceLevel = "medium"
	ConfidenceLow    ConfidenceLevel = "low"
)

// Step is a single remediation action.
type Step struct {
	StepNumber  int             `json:"step_number"`
	Title       string          `json:"title"`
	SafeDefault bool            `json:"safe_default"`
	Caution     string          `json:"caution,omitempty"`
	Action      string          `json:"action"`
	Confidence  ConfidenceLevel `json:"confidence"`
}

// ChainContext describes the compound chain membership.
type ChainContext struct {
	ChainID           kernel.ChainID     `json:"chain_id"`
	ChainActive       bool               `json:"chain_active"`
	MemberControls    []ChainMember      `json:"member_controls"`
	ChainNarrative    string             `json:"chain_narrative"`
	DeactivationOrder []kernel.ControlID `json:"deactivation_order,omitempty"`
}

// MemberStatus classifies the status of a chain member control.
type MemberStatus string

// ChainMember status vocabulary. Centralised here so producers and
// consumers can't drift on the literal strings.
const (
	StatusThisFinding MemberStatus = "this_finding"
	StatusAlsoFailing MemberStatus = "also_failing"
	StatusPassing     MemberStatus = "passing"
)

// ChainMember is a single control in a chain.
type ChainMember struct {
	ControlID kernel.ControlID `json:"control_id"`
	Status    MemberStatus     `json:"status"` // see Status* constants above
}

// IsPassing reports whether this chain member is currently in the
// passing state (no active finding) — the threshold consumers use
// to decide whether to render a deactivation hint or skip the
// member entirely. Replaces (m.Status == "passing") probes in
// cmd/diagnose so the caller stops comparing to a literal.
func (m *ChainMember) IsPassing() bool {
	return m != nil && m.Status == StatusPassing
}

// StatusIcon returns the unicode marker the cmd/diagnose narrative
// renderer prefixes member-control rows with: a check mark when
// the member is passing, a cross when it is failing or holding
// a finding. Replaces the `icon := "✗"; if IsPassing { icon = "✓" }`
// branch in the explain-narrative renderer so the rendering choice
// stays on the type that owns Status.
func (m *ChainMember) StatusIcon() string {
	if m != nil && m.IsPassing() {
		return "✓"
	}
	return "✗"
}

// StatusGlyph returns the ASCII fallback the markdown variant of
// the explain-narrative renderer uses when the unicode StatusIcon
// won't render: "v" for passing, "x" otherwise. Sibling of
// StatusIcon for the markdown renderer.
func (m *ChainMember) StatusGlyph() string {
	if m != nil && m.IsPassing() {
		return "v"
	}
	return "x"
}

// Input holds data for building a playbook.
type Input struct {
	Finding     remediation.Finding
	Control     *policy.ControlDefinition
	ChainDefs   []policy.ChainDefinition
	AllFindings []remediation.Finding // for chain member status lookup
}

// BuildPlaybook assembles a narrative playbook from structured data.
func BuildPlaybook(input *Input) Playbook {
	if input == nil {
		return Playbook{}
	}
	f := &input.Finding

	pb := Playbook{
		FindingID:   string(f.FindingID),
		ControlID:   f.ControlID,
		AssetID:     f.AssetID,
		Severity:    f.ControlSeverity,
		ControlName: f.ControlName,
	}

	// Section 2: Why this matters.
	pb.Narrative.WhyThisMatters = buildWhySection(f, input.Control)

	// Attack stage.
	if input.Control != nil {
		pb.Narrative.AttackStage = input.Control.AttackStage()
	}

	// Section 3: Current state from changes.
	pb.Narrative.CurrentState = buildCurrentState(f.RemediationSpec.Changes)

	// Section 4: Remediation steps with dependency ordering.
	pb.Narrative.Steps = buildSteps(f.RemediationSpec)

	// Section 5: Chain context.
	if f.IsChainMember() {
		pb.Narrative.ChainContext = buildChainContext(f, input.ChainDefs, input.AllFindings)
	}

	return pb
}

func buildWhySection(f *remediation.Finding, ctl *policy.ControlDefinition) string {
	var parts []string

	if f.ControlDescription != "" {
		parts = append(parts, f.ControlDescription)
	}

	if ctl != nil {
		if stage := ctl.AttackStage(); stage != "" {
			parts = append(parts, "Attack stage: "+strings.ToUpper(string(stage)))
		}
	}

	if f.HasReachability() && f.Reachability.TotalReachablePrincipals > 0 {
		reach := fmt.Sprintf("Reachability: %d principal(s) can reach this resource",
			f.Reachability.TotalReachablePrincipals)
		if f.Reachability.PrivilegedPrincipalCount > 0 {
			reach += fmt.Sprintf(" (%d privileged)", f.Reachability.PrivilegedPrincipalCount)
		}
		parts = append(parts, reach)
	}

	return strings.Join(parts, "\n")
}

func buildCurrentState(changes []policy.PropertyChange) []StateEntry {
	entries := make([]StateEntry, len(changes))
	for i, c := range changes {
		entries[i] = StateEntry{
			PropertyPath:   c.PropertyPath,
			CurrentValue:   c.CurrentValue,
			RequiredValue:  c.RequiredValue,
			HasSafeDefault: c.HasSafeDefault,
		}
	}
	return entries
}

func buildSteps(spec policy.RemediationSpec) []Step {
	if len(spec.Changes) == 0 && spec.Action != "" {
		return []Step{{
			StepNumber: 1,
			Title:      "Apply remediation",
			Action:     spec.Action,
			Confidence: confidenceLabel(spec.Confidence),
		}}
	}

	// Sort: safe-default changes first, then unsafe ones last.
	sorted := slices.Clone(spec.Changes)
	slices.SortFunc(sorted, func(a, b policy.PropertyChange) int {
		if a.HasSafeDefault && !b.HasSafeDefault {
			return -1
		}
		if !a.HasSafeDefault && b.HasSafeDefault {
			return 1
		}
		return cmp.Compare(a.PropertyPath, b.PropertyPath)
	})

	// Group changes by namespace (first path component).
	groups := groupByNamespace(sorted)

	steps := make([]Step, 0, len(groups))
	for i, g := range groups {
		step := Step{
			StepNumber:  i + 1,
			Title:       "Set " + g.namespace,
			SafeDefault: g.allSafe,
			Confidence:  confidenceLabel(spec.Confidence),
		}

		var actionParts []string
		for _, c := range g.changes {
			actionParts = append(actionParts,
				fmt.Sprintf("  %s: %s → %s", c.PropertyPath, c.CurrentValue, c.RequiredValue))
		}
		step.Action = strings.Join(actionParts, "\n")

		if !g.allSafe {
			step.Caution = "This change may affect existing behavior. Verify dependencies before applying."
		}

		if spec.Action != "" && i == 0 {
			step.Action = spec.Action + "\n" + step.Action
		}

		steps = append(steps, step)
	}

	if len(steps) == 0 && spec.Action != "" {
		steps = append(steps, Step{
			StepNumber: 1,
			Title:      "Apply remediation",
			Action:     spec.Action,
			Confidence: confidenceLabel(spec.Confidence),
		})
	}

	return steps
}

type changeGroup struct {
	namespace string
	changes   []policy.PropertyChange
	allSafe   bool
}

func groupByNamespace(changes []policy.PropertyChange) []changeGroup {
	if len(changes) == 0 {
		return nil
	}

	groups := make(map[string]*changeGroup)
	var order []string
	for _, c := range changes {
		ns := c.PropertyPath
		if idx := strings.IndexByte(ns, '.'); idx > 0 {
			ns = ns[:idx]
		}
		g, ok := groups[ns]
		if !ok {
			g = &changeGroup{namespace: ns, allSafe: true}
			groups[ns] = g
			order = append(order, ns)
		}
		g.changes = append(g.changes, c)
		if !c.HasSafeDefault {
			g.allSafe = false
		}
	}

	result := make([]changeGroup, len(order))
	for i, ns := range order {
		result[i] = *groups[ns]
	}
	return result
}

func buildChainContext(f *remediation.Finding, chainDefs []policy.ChainDefinition, allFindings []remediation.Finding) *ChainContext {
	if !f.IsChainMember() {
		return nil
	}

	primaryID := kernel.ChainID(f.PrimaryChainID())

	// Find the chain definition.
	var chainDef *policy.ChainDefinition
	for i := range chainDefs {
		if chainDefs[i].ID == primaryID {
			chainDef = &chainDefs[i]
			break
		}
	}

	ctx := &ChainContext{
		ChainID:        primaryID,
		ChainActive:    true,
		ChainNarrative: f.PrimaryChainNarrative(),
	}

	// Build member control status.
	failingIDs := make(map[kernel.ControlID]struct{}, len(allFindings))
	for i := range allFindings {
		if allFindings[i].AssetID == f.AssetID {
			failingIDs[allFindings[i].ControlID] = struct{}{}
		}
	}

	if chainDef != nil {
		for _, ctlID := range chainDef.ControlIDs {
			status := StatusPassing
			if ctlID == f.ControlID {
				status = StatusThisFinding
			} else if _, ok := failingIDs[ctlID]; ok {
				status = StatusAlsoFailing
			}
			ctx.MemberControls = append(ctx.MemberControls, ChainMember{
				ControlID: ctlID,
				Status:    status,
			})
		}

		// Deactivation order: detection → crypto → exposure.
		ctx.DeactivationOrder = chainDeactivationOrder(chainDef.ControlIDs)
	}

	return ctx
}

// chainDeactivationOrder sorts control IDs by the recommended
// remediation order: restore detection first, then crypto, then
// remove exposure. Based on attack stage conventions.
func chainDeactivationOrder(controlIDs []kernel.ControlID) []kernel.ControlID {
	order := make([]kernel.ControlID, len(controlIDs))
	copy(order, controlIDs)
	slices.SortFunc(order, func(a, b kernel.ControlID) int {
		if n := stageOrder(a) - stageOrder(b); n != 0 {
			return n
		}
		return cmp.Compare(string(a), string(b))
	})
	return order
}

func stageOrder(controlID kernel.ControlID) int {
	id := strings.ToUpper(string(controlID))
	switch {
	case strings.Contains(id, "TRAIL") || strings.Contains(id, "LOG") || strings.Contains(id, "AUDIT"):
		return 0 // detection first
	case strings.Contains(id, "KMS") || strings.Contains(id, "ENCRYPT") || strings.Contains(id, "CERT"):
		return 1 // crypto second
	default:
		return 2 // exposure last
	}
}

func confidenceLabel(c float64) ConfidenceLevel {
	switch {
	case c >= 0.9:
		return ConfidenceHigh
	case c >= 0.6:
		return ConfidenceMedium
	case c > 0:
		return ConfidenceLow
	default:
		return ""
	}
}
