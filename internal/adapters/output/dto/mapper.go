package dto

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/fp"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// FromEvaluation projects a safetyenvelope.Evaluation into a ResultDTO.
func FromEvaluation(e safetyenvelope.Evaluation) ResultDTO {
	return ResultDTO{
		SchemaVersion:      e.SchemaVersion,
		Kind:               string(e.Kind),
		Run:                fromRunInfo(e.Run),
		Summary:            fromSummary(e.Summary),
		Findings:           fromFindings(e.Findings),
		SuppressedFindings: fromSuppressedFindings(e.SuppressedFindings),
		RemediationGroups:  fromRemediationGroups(e.RemediationGroups),
		Skipped:            fromSkippedControls(e.Skipped),
		SkippedAssets:      fromSkippedAssets(e.SkippedAssets),
		Extensions:         fromExtensions(e.Extensions),
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
	return fp.Map(fs, FromFinding)
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
		dto.Misconfigurations = fp.Map(e.Misconfigurations, fromMisconfiguration)
	}

	if len(e.RootCauses) > 0 {
		dto.RootCauses = fp.Map(e.RootCauses, evaluation.RootCause.String)
	}

	if e.SourceEvidence != nil {
		dto.SourceEvidence = &SourceEvidenceDTO{
			PolicyPublicStatements: e.SourceEvidence.PolicyPublicStatements,
			ACLPublicGrantees:      e.SourceEvidence.ACLPublicGrantees,
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
		dto.Actions = fp.Map(p.Actions, fromRemediationAction)
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
		ToolVersion: r.ToolVersion,
		Offline:     r.Offline,
		Now:         r.Now,
		MaxUnsafe:   r.MaxUnsafe,
		Snapshots:   r.Snapshots,
		PackHash:    r.PackHash,
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
	files := make(map[string]kernel.Digest, len(h.Files))
	for k, v := range h.Files {
		files[string(k)] = v
	}
	return &InputHashesDTO{
		Files:   files,
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

func fromSuppressedFindings(fs []evaluation.SuppressedFinding) []SuppressedFindingDTO {
	if len(fs) == 0 {
		return nil
	}
	out := make([]SuppressedFindingDTO, len(fs))
	for i, f := range fs {
		out[i] = SuppressedFindingDTO{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
			Reason:    f.Reason,
			Expires:   f.Expires,
		}
	}
	return out
}

func fromRemediationGroups(gs []remediation.Group) []RemediationGroupDTO {
	if len(gs) == 0 {
		return nil
	}
	out := make([]RemediationGroupDTO, len(gs))
	for i, g := range gs {
		out[i] = RemediationGroupDTO{
			AssetID:              g.AssetID,
			AssetType:            g.AssetType,
			RemediationPlan:      fromRemediationPlan(g.RemediationPlan),
			ContributingControls: g.ContributingControls,
			FindingCount:         g.FindingCount,
		}
	}
	return out
}

func fromSkippedControls(cs []evaluation.SkippedControl) []SkippedControlDTO {
	if len(cs) == 0 {
		return nil
	}
	out := make([]SkippedControlDTO, len(cs))
	for i, c := range cs {
		out[i] = SkippedControlDTO{
			ControlID:   c.ControlID,
			ControlName: c.ControlName,
			Reason:      c.Reason,
		}
	}
	return out
}

func fromSkippedAssets(as []asset.SkippedAsset) []SkippedAssetDTO {
	if len(as) == 0 {
		return nil
	}
	out := make([]SkippedAssetDTO, len(as))
	for i, a := range as {
		out[i] = SkippedAssetDTO{
			AssetID: a.ID,
			Pattern: a.Pattern,
			Reason:  a.Reason,
		}
	}
	return out
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
