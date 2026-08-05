package dto

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// NewRunInfoDTO is the DTO-side constructor for evaluation.RunInfo.
// The DTO owns the wire format and the conversion from the domain
// shape so callers don't need a separate "mapper" intermediary —
// the wire-side type knows how to build itself from a domain
// value. Mirrored on the other DTOs in this file.
func NewRunInfoDTO(r evaluation.RunInfo) RunInfoDTO {
	dto := RunInfoDTO{
		StaveVersion:      r.StaveVersion,
		Offline:           r.Offline,
		EvalTime:          r.EvalTime,
		MaxUnsafeDuration: r.MaxUnsafeDuration,
		Snapshots:         r.Snapshots,
		PolicyFingerprint: r.PolicyFingerprint,
		EvaluatedState:    r.EvaluatedState,
	}
	if r.InputHashes != nil {
		dto.InputHashes = NewInputHashesDTO(r.InputHashes)
	}
	return dto
}

// NewInputHashesDTO is the DTO-side constructor for the input-hash
// envelope. Returns nil when the source is nil so callers stop
// open-coding the nil-check at every site.
func NewInputHashesDTO(h *evaluation.InputHashes) *InputHashesDTO {
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

// NewSummaryDTO is the DTO-side constructor for the compliance
// summary's wire shape.
func NewSummaryDTO(s evaluation.ComplianceSummary) SummaryDTO {
	return SummaryDTO{
		TotalAssets:      s.TotalAssets,
		ExposedResources: s.ExposedResources,
		Violations:       s.Violations,
		Indeterminate:    s.Indeterminate,
	}
}

func packNamesToStrings(packs []kernel.PackName) []string {
	if packs == nil {
		return nil
	}
	out := make([]string, len(packs))
	for i, p := range packs {
		out[i] = string(p)
	}
	return out
}

// NewExtensionsDTO is the DTO-side constructor for the extensions
// metadata envelope.
func NewExtensionsDTO(e *evaluation.Extensions) *ExtensionsDTO {
	if e == nil {
		return nil
	}
	dto := &ExtensionsDTO{
		SelectedSource:      e.SelectedSource,
		ContextName:         e.ContextName,
		ResolvedPaths:       e.ResolvedPaths,
		EnabledPacks:        packNamesToStrings(e.EnabledPacks),
		ResolvedControlIDs:  e.ResolvedControlIDs,
		PackRegistryVersion: e.PackRegistryVersion,
		PackRegistryHash:    e.PackRegistryHash,
	}
	return dto
}
