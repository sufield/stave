package dto

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/translation"
)

// FromFinding projects a single remediation.Finding into a FindingDTO.
func FromFinding(f *remediation.Finding) FindingDTO {
	dto := FindingDTO{
		FindingID:          f.FindingID,
		ControlID:          f.ControlID,
		ControlName:        f.ControlName,
		ControlDescription: f.ControlDescription,
		AssetID:            f.AssetID,
		AssetType:          f.AssetType,
		AssetVendor:        f.AssetVendor,
		Evidence:           fromEvidence(f.Evidence),
		ControlSeverity:    f.ControlSeverity.String(),
		ControlCompliance:  complianceToStrings(f.ControlCompliance),
		ControlCCMV4:       f.ControlCCMV4,
		Remediation:        fromRemediationSpec(f.RemediationSpec),
		Classification:     string(f.Classification),
		ScopeTags:          scopeTagsToStrings(f.ScopeTags),
		Defect:             f.Defect,
		Infection:          f.Infection,
		Failure:            f.Failure,
		Delta:              fromDeltaPaths(f.Delta),
	}

	if f.Source != nil {
		dto.Source = &SourceRefDTO{File: f.Source.File, Line: f.Source.Line}
	}
	if f.Exposure != nil {
		dto.Exposure = &ExposureDTO{
			Type:           string(f.Exposure.Type),
			PrincipalScope: f.Exposure.PrincipalScope.String(),
		}
	}
	if f.PostureDrift != nil {
		dto.PostureDrift = &PostureDriftDTO{
			Pattern:             f.PostureDrift.Pattern,
			ExposureWindowCount: f.PostureDrift.ExposureWindowCount,
		}
	}
	if f.RemediationPlan != nil {
		plan := fromRemediationPlan(*f.RemediationPlan)
		dto.RemediationPlan = &plan
	}
	if len(f.ChainMembership) > 0 {
		dto.ChainMembership = mapSlice(f.ChainMembership, fromChainMembershipEntry)
	}

	dto.SLADeadlineHours = f.SLADeadlineHours
	dto.SLABreached = f.SLABreached
	dto.SLAOverdueHours = f.SLAOverdueHours
	dto.SLAEscalatedSeverity = f.SLAEscalatedSeverity
	dto.SLAPolicySource = f.SLAPolicySource
	dto.ExposureScore = f.ExposureScore
	dto.ScoreBreakdown = f.ScoreBreakdown
	if len(f.ReasoningTrace) > 0 {
		dto.ReasoningTrace = make([]MatchedClauseDTO, len(f.ReasoningTrace))
		for i, mc := range f.ReasoningTrace {
			dto.ReasoningTrace[i] = MatchedClauseDTO{
				PredicateExpr:  mc.PredicateExpr,
				ObservationKey: mc.ObservationKey,
				Operator:       mc.Operator,
				ExpectedValue:  mc.ExpectedValue,
				ObservedValue:  mc.ObservedValue,
			}
		}
	}
	dto.RemediationContext = buildRemediationContext(f)
	if len(f.Alternatives) > 0 {
		dto.Alternatives = make([]AlternativeDTO, len(f.Alternatives))
		for i, a := range f.Alternatives {
			dto.Alternatives[i] = AlternativeDTO{
				Tool:     a.Tool,
				CheckID:  a.CheckID,
				Coverage: string(a.Coverage),
				Note:     a.Note,
			}
		}
	}

	// Normalize empty severity to match omitempty behavior.
	if dto.ControlSeverity == "" {
		dto.ControlSeverity = ""
	}
	if len(dto.ControlCompliance) == 0 {
		dto.ControlCompliance = nil
	}

	return dto
}

// buildRemediationContext packages the asset identity, violation
// reasoning, structured changes, and the asset-parameterized command
// in one shape downstream consumers can feed into AI prompts or
// ticketing. See docs/product/metrics.md § Metric 4.
func buildRemediationContext(f *remediation.Finding) *RemediationContextDTO {
	// Skip when the finding has neither reasoning nor remediation to
	// package — avoids emitting empty context blocks.
	hasTrace := len(f.ReasoningTrace) > 0
	hasSpec := f.RemediationSpec.Action != "" || f.RemediationSpec.Description != ""
	if !hasTrace && !hasSpec {
		return nil
	}

	ctx := &RemediationContextDTO{
		Asset: RemediationAssetDTO{
			ID:     string(f.AssetID),
			Type:   string(f.AssetType),
			Vendor: string(f.AssetVendor),
		},
		Violation: RemediationViolationDTO{
			ControlID:   string(f.ControlID),
			ControlName: f.ControlName,
			Severity:    f.ControlSeverity.String(),
		},
	}

	// Asset ARN + region when derivable from an ARN-shaped AssetID.
	if strings.HasPrefix(string(f.AssetID), "arn:aws:") {
		ctx.Asset.ARN = string(f.AssetID)
		parts := strings.SplitN(string(f.AssetID), ":", 6)
		if len(parts) == 6 {
			ctx.Asset.Region = parts[3]
		}
	}

	// Reasoning: mirror each matched clause in a structured shape
	// paired with its plain-English rendering.
	for _, mc := range f.ReasoningTrace {
		ctx.Violation.Reasoning = append(ctx.Violation.Reasoning, RemediationReasoningDTO{
			Clause: translation.RenderClause(translation.Clause{
				ObservationKey: mc.ObservationKey,
				Operator:       mc.Operator,
				ExpectedValue:  mc.ExpectedValue,
				ObservedValue:  mc.ObservedValue,
			}, translation.DefaultFieldRegistry),
			ObservationKey: mc.ObservationKey,
			ObservedValue:  mc.ObservedValue,
		})
	}

	// Changes: derive on the fly from misconfigurations; propagate
	// the spec's RequiredValuePrompt onto each HasSafeDefault=false
	// entry.
	changes := policy.DeriveChanges(f.Evidence.Misconfigurations)
	for i := range changes {
		if !changes[i].HasSafeDefault && f.RemediationSpec.RequiredValuePrompt != "" {
			changes[i].RequiredValuePrompt = f.RemediationSpec.RequiredValuePrompt
		}
		ctx.Changes = append(ctx.Changes, PropertyChangeDTO{
			Path:                changes[i].PropertyPath,
			CurrentValue:        changes[i].CurrentValue,
			RequiredValue:       changes[i].RequiredValue,
			RequiredValuePrompt: changes[i].RequiredValuePrompt,
			HasSafeDefault:      changes[i].HasSafeDefault,
			Description:         changes[i].Description,
		})
	}

	if f.RemediationPlan != nil && f.RemediationPlan.Command != "" {
		ctx.Action = f.RemediationPlan.Command
	}

	return ctx
}

func fromFindings(fs []remediation.Finding) []FindingDTO {
	if fs != nil && len(fs) == 0 {
		return []FindingDTO{}
	}
	return mapSlice(fs, func(f remediation.Finding) FindingDTO { return FromFinding(&f) })
}

func fromEvidence(e evaluation.Evidence) EvidenceDTO {
	dto := EvidenceDTO{
		FirstUnsafeAt:         e.FirstUnsafeAt,
		LastSeenUnsafeAt:      e.LastSeenUnsafeAt,
		UnsafeDurationHours:   e.UnsafeDurationHours,
		ThresholdHours:        e.ThresholdHours,
		ExposureWindowCount:   e.ExposureWindowCount,
		WindowDays:            e.WindowDays,
		RecurrenceLimit:       e.RecurrenceLimit,
		FirstExposureWindowAt: e.FirstExposureWindowAt,
		LastExposureWindowAt:  e.LastExposureWindowAt,
		TemporalRisk:          e.TemporalRisk,
	}

	if len(e.Misconfigurations) > 0 {
		dto.Misconfigurations = mapSlice(e.Misconfigurations, func(m policy.Misconfiguration) MisconfigurationDTO { return fromMisconfiguration(m) })
	}

	if len(e.RootCauses) > 0 {
		dto.RootCauses = mapSlice(e.RootCauses, func(c evaluation.RootCause) string { return c.String() })
	}

	if e.SourceEvidence != nil {
		dto.SourceEvidence = &SourceEvidenceDTO{
			IdentityStatements: kernel.StringsFrom(e.SourceEvidence.IdentityStatements),
			ResourceGrantees:   kernel.StringsFrom(e.SourceEvidence.ResourceGrantees),
		}
	}

	return dto
}

func fromMisconfiguration(m policy.Misconfiguration) MisconfigurationDTO {
	return MisconfigurationDTO{
		Property:    m.Property.String(),
		ActualValue: m.ActualValue,
		Operator:    string(m.Operator),
		UnsafeValue: m.UnsafeValue,
	}
}

func fromRemediationSpec(s policy.RemediationSpec) RemediationSpecDTO {
	return RemediationSpecDTO{
		Description: s.Description,
		Action:      s.Action,
		Example:     s.Example,
	}
}

func fromRemediationPlan(p evaluation.RemediationPlan) RemediationPlanDTO {
	dto := RemediationPlanDTO{
		ID: string(p.ID),
		Target: RemediationTargetDTO{
			AssetID:   p.Target.AssetID,
			AssetType: p.Target.AssetType,
		},
		Preconditions:  p.Preconditions,
		ExpectedEffect: p.ExpectedEffect,
		Action:         p.Command,
	}
	if len(p.Actions) > 0 {
		dto.Actions = mapSlice(p.Actions, func(a evaluation.RemediationAction) RemediationActionDTO { return fromRemediationAction(a) })
	}
	return dto
}

func fromDeltaPaths(ds []policy.DeltaPath) []DeltaPathDTO {
	if len(ds) == 0 {
		return nil
	}
	out := make([]DeltaPathDTO, len(ds))
	for i, d := range ds {
		out[i] = DeltaPathDTO{
			PropertyLabel: d.PropertyLabel,
			PropertyPath:  d.PropertyPath,
			CurrentValue:  d.CurrentValue,
			FixAction:     d.FixAction,
		}
	}
	return out
}

func fromRemediationAction(a evaluation.RemediationAction) RemediationActionDTO {
	return RemediationActionDTO{
		ActionType: a.ActionType,
		Path:       a.Path.String(),
		Value:      a.Value,
	}
}

func fromChainMembershipEntry(e evaluation.ChainMembershipEntry) ChainMembershipEntryDTO {
	return ChainMembershipEntryDTO{
		ChainID:       e.ChainID,
		ChainSeverity: e.ChainSeverity,
		StageSpan:     e.StageSpan,
		Narrative:     e.Narrative,
	}
}

func fromExceptedFindings(fs []evaluation.ExceptedFinding) []ExceptedFindingDTO {
	if len(fs) == 0 {
		return nil
	}
	return mapSlice(fs, func(f evaluation.ExceptedFinding) ExceptedFindingDTO {
		return ExceptedFindingDTO{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
			Reason:    f.Reason,
			Expires:   f.Expires.String(),
		}
	})
}

func fromRemediationGroups(gs []remediation.Group) []RemediationGroupDTO {
	if len(gs) == 0 {
		return nil
	}
	return mapSlice(gs, func(g remediation.Group) RemediationGroupDTO {
		return RemediationGroupDTO{
			AssetID:              g.AssetID,
			AssetType:            g.AssetType,
			RemediationPlan:      fromRemediationPlan(g.RemediationPlan),
			ContributingControls: g.ContributingControls,
			FindingCount:         g.FindingCount,
		}
	})
}

func fromSkippedControls(cs []evaluation.SkippedControl) []SkippedControlDTO {
	if len(cs) == 0 {
		return nil
	}
	return mapSlice(cs, func(c evaluation.SkippedControl) SkippedControlDTO {
		return SkippedControlDTO{
			ControlID:   c.ControlID,
			ControlName: c.ControlName,
			Reason:      c.Reason,
		}
	})
}

func fromExemptedAssets(as []asset.ExemptedAsset) []ExemptedAssetDTO {
	if len(as) == 0 {
		return nil
	}
	return mapSlice(as, func(a asset.ExemptedAsset) ExemptedAssetDTO {
		return ExemptedAssetDTO{
			AssetID: a.ID,
			Pattern: a.Pattern,
			Reason:  a.Reason,
		}
	})
}

func fromAtRiskItems(items risk.ThresholdItems) []AtRiskItemDTO {
	if len(items) == 0 {
		return nil
	}
	return mapSlice(items, func(item risk.ThresholdItem) AtRiskItemDTO {
		return AtRiskItemDTO{
			ControlID:      item.ControlID,
			AssetID:        item.AssetID,
			AssetType:      item.AssetType,
			Status:         string(item.Status),
			DueAt:          item.DueAt,
			RemainingHours: item.Remaining.Hours(),
			FirstUnsafeAt:  item.FirstUnsafeAt,
			ThresholdHours: item.Threshold.Hours(),
		}
	})
}

func complianceToStrings(m policy.ComplianceMapping) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[string(k)] = v
	}
	return out
}

func scopeTagsToStrings(tags []kernel.ScopeTag) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = string(t)
	}
	return out
}
