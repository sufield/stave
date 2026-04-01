package dto

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func fromRunInfo(r evaluation.RunInfo) RunInfoDTO {
	dto := RunInfoDTO{
		StaveVersion:      r.StaveVersion,
		Offline:           r.Offline,
		Now:               r.Now,
		MaxUnsafeDuration: r.MaxUnsafeDuration,
		Snapshots:         r.Snapshots,
		PackHash:          r.PackHash,
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
