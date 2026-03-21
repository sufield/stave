package dto

import (
	"github.com/samber/lo"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// FromEvaluation projects a safetyenvelope.Evaluation into a ResultDTO.
func FromEvaluation(e safetyenvelope.Evaluation) ResultDTO {
	return ResultDTO{
		SchemaVersion:     e.SchemaVersion,
		Kind:              string(e.Kind),
		Run:               fromRunInfo(e.Run),
		Summary:           fromSummary(e.Summary),
		Findings:          fromFindings(e.Findings),
		ExceptedFindings:  fromExceptedFindings(e.ExceptedFindings),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		Skipped:           fromSkippedControls(e.Skipped),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
		Extensions:        fromExtensions(e.Extensions),
	}
}

// FromFinding projects a single remediation.Finding into a FindingDTO.
func FromFinding(f remediation.Finding) FindingDTO {
	dto := FindingDTO{
		ControlID:          f.ControlID,
		ControlName:        f.ControlName,
		ControlDescription: f.ControlDescription,
		AssetID:            f.AssetID,
		AssetType:          f.AssetType,
		AssetVendor:        f.AssetVendor,
		Evidence:           fromEvidence(f.Evidence),
		ControlSeverity:    f.ControlSeverity.String(),
		ControlCompliance:  map[string]string(f.ControlCompliance),
		Remediation:        fromRemediationSpec(f.RemediationSpec),
	}

	if f.Source != nil {
		dto.Source = &SourceRefDTO{File: f.Source.File, Line: f.Source.Line}
	}
	if f.Exposure != nil {
		dto.Exposure = &ExposureDTO{
			Type:           f.Exposure.Type,
			PrincipalScope: f.Exposure.PrincipalScope.String(),
		}
	}
	if f.PostureDrift != nil {
		dto.PostureDrift = &PostureDriftDTO{
			Pattern:      f.PostureDrift.Pattern,
			EpisodeCount: f.PostureDrift.EpisodeCount,
		}
	}
	if f.RemediationPlan != nil {
		plan := fromRemediationPlan(*f.RemediationPlan)
		dto.RemediationPlan = &plan
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

func fromFindings(fs []remediation.Finding) []FindingDTO {
	if fs != nil && len(fs) == 0 {
		return []FindingDTO{}
	}
	return lo.Map(fs, func(f remediation.Finding, _ int) FindingDTO { return FromFinding(f) })
}

func fromEvidence(e evaluation.Evidence) EvidenceDTO {
	dto := EvidenceDTO{
		FirstUnsafeAt:       e.FirstUnsafeAt,
		LastSeenUnsafeAt:    e.LastSeenUnsafeAt,
		UnsafeDurationHours: e.UnsafeDurationHours,
		ThresholdHours:      e.ThresholdHours,
		EpisodeCount:        e.EpisodeCount,
		WindowDays:          e.WindowDays,
		RecurrenceLimit:     e.RecurrenceLimit,
		FirstEpisodeAt:      e.FirstEpisodeAt,
		LastEpisodeAt:       e.LastEpisodeAt,
		WhyNow:              e.WhyNow,
	}

	if len(e.Misconfigurations) > 0 {
		dto.Misconfigurations = lo.Map(e.Misconfigurations, func(m policy.Misconfiguration, _ int) MisconfigurationDTO { return fromMisconfiguration(m) })
	}

	if len(e.RootCauses) > 0 {
		dto.RootCauses = lo.Map(e.RootCauses, func(c evaluation.RootCause, _ int) string { return c.String() })
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
		Property:    m.Property,
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
		ID: p.ID,
		Target: RemediationTargetDTO{
			AssetID:   p.Target.AssetID,
			AssetType: p.Target.AssetType,
		},
		Preconditions:  p.Preconditions,
		ExpectedEffect: p.ExpectedEffect,
	}
	if len(p.Actions) > 0 {
		dto.Actions = lo.Map(p.Actions, func(a evaluation.RemediationAction, _ int) RemediationActionDTO { return fromRemediationAction(a) })
	}
	return dto
}

func fromRemediationAction(a evaluation.RemediationAction) RemediationActionDTO {
	return RemediationActionDTO{
		ActionType: a.ActionType,
		Path:       a.Path,
		Value:      a.Value,
	}
}

func fromRunInfo(r evaluation.RunInfo) RunInfoDTO {
	dto := RunInfoDTO{
		StaveVersion: r.StaveVersion,
		Offline:      r.Offline,
		Now:          r.Now,
		MaxUnsafe:    r.MaxUnsafe,
		Snapshots:    r.Snapshots,
		PackHash:     r.PackHash,
	}
	if r.InputHashes != nil {
		dto.InputHashes = fromInputHashes(r.InputHashes)
	}
	return dto
}

func fromInputHashes(h *evaluation.InputHashes) *InputHashesDTO {
	if h == nil {
		return nil
	}
	return &InputHashesDTO{
		Files:   lo.MapKeys(h.Files, func(_ kernel.Digest, k evaluation.FilePath) string { return string(k) }),
		Overall: h.Overall,
	}
}

func fromSummary(s evaluation.Summary) SummaryDTO {
	return SummaryDTO{
		AssetsEvaluated: s.AssetsEvaluated,
		AttackSurface:   s.AttackSurface,
		Violations:      s.Violations,
	}
}

func fromExceptedFindings(fs []evaluation.ExceptedFinding) []ExceptedFindingDTO {
	if len(fs) == 0 {
		return nil
	}
	return lo.Map(fs, func(f evaluation.ExceptedFinding, _ int) ExceptedFindingDTO {
		return ExceptedFindingDTO{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
			Reason:    f.Reason,
			Expires:   f.Expires,
		}
	})
}

func fromRemediationGroups(gs []remediation.Group) []RemediationGroupDTO {
	if len(gs) == 0 {
		return nil
	}
	return lo.Map(gs, func(g remediation.Group, _ int) RemediationGroupDTO {
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
	return lo.Map(cs, func(c evaluation.SkippedControl, _ int) SkippedControlDTO {
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
	return lo.Map(as, func(a asset.ExemptedAsset, _ int) ExemptedAssetDTO {
		return ExemptedAssetDTO{
			AssetID: a.ID,
			Pattern: a.Pattern,
			Reason:  a.Reason,
		}
	})
}

func fromExtensions(e *evaluation.Extensions) *ExtensionsDTO {
	if e == nil {
		return nil
	}
	dto := &ExtensionsDTO{
		SelectedSource:      e.SelectedSource,
		ContextName:         e.ContextName,
		ResolvedPaths:       e.ResolvedPaths,
		EnabledPacks:        e.EnabledPacks,
		ResolvedControlIDs:  e.ResolvedControlIDs,
		PackRegistryVersion: e.PackRegistryVersion,
		PackRegistryHash:    e.PackRegistryHash,
	}
	if e.Git != nil {
		dto.Git = &GitMetadataDTO{
			RepoRoot: e.Git.RepoRoot,
			Head:     e.Git.Head,
			Dirty:    e.Git.Dirty,
			Modified: e.Git.Modified,
		}
	}
	return dto
}
