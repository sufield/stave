package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/securityaudit"
)

// --- Vuln evidence payload structs ---

type vulnLiveReport struct {
	Source       string         `json:"source"`
	GeneratedAt  string         `json:"generated_at"`
	FindingCount int            `json:"finding_count"`
	Provenance   vulnProvenance `json:"provenance"`
	RawStream    string         `json:"raw_stream"`
}

type vulnProvenance struct {
	Tool string `json:"tool"`
	Mode string `json:"mode"`
}

type vulnArtifactWrapper struct {
	Source       string          `json:"source"`
	Path         string          `json:"path"`
	FindingCount int             `json:"finding_count"`
	LoadedAt     string          `json:"loaded_at"`
	Raw          json.RawMessage `json:"raw"`
}

type vulnFallbackEnvelope struct {
	Source       VulnSourceUsed `json:"source"`
	Available    bool           `json:"available"`
	Freshness    VulnFreshness  `json:"freshness"`
	FindingCount int            `json:"finding_count"`
	Details      string         `json:"details"`
	GeneratedAt  string         `json:"generated_at"`
}

type DefaultVulnProvider struct {
	RunGovulncheck VulnerabilityScanner
	ReadFile       func(path string) ([]byte, error)
	StatFile       func(string) (fs.FileInfo, error)
}

func (p DefaultVulnProvider) Resolve(ctx context.Context, req Params) (VulnerabilitySnapshot, error) {
	if shouldAttemptLiveCheck(req) {
		live, liveErr := executeGovulncheck(ctx, req.Cwd, p.RunGovulncheck, req.Now)
		if liveErr == nil {
			return ensureVulnRawJSON(live, req.Now), nil
		}
		// Keep fallback behavior but preserve the live-check failure reason.
		fallback, err := p.resolveVulnFallback(req)
		if err == nil && fallback.Available {
			fallback.Details = fmt.Sprintf("live check failed (%v); used fallback evidence", liveErr)
			return ensureVulnRawJSON(fallback, req.Now), nil
		}
		return ensureVulnRawJSON(VulnerabilitySnapshot{
			Available:    false,
			SourceUsed:   VulnSourceUsedFailed,
			Freshness:    FreshnessUnknown,
			FindingCount: 0,
			Details:      fmt.Sprintf("govulncheck execution failed: %v", liveErr),
		}, req.Now), nil
	}
	fallback, err := p.resolveVulnFallback(req)
	if err != nil {
		return VulnerabilitySnapshot{}, err
	}
	return ensureVulnRawJSON(fallback, req.Now), nil
}

func shouldAttemptLiveCheck(req Params) bool {
	if !req.LiveVulnCheck {
		return false
	}
	return req.VulnSource == VulnSourceLocal || req.VulnSource == VulnSourceHybrid
}

func (p DefaultVulnProvider) resolveVulnFallback(req Params) (VulnerabilitySnapshot, error) {
	if req.VulnSource == VulnSourceLocal || req.VulnSource == VulnSourceHybrid {
		if cached, ok := p.loadVulnEvidenceFromCandidates(localVulnEvidenceCandidates(req), req.Now); ok {
			return cached, nil
		}
	}
	if req.VulnSource == VulnSourceCI || req.VulnSource == VulnSourceHybrid {
		if ciEvidence, ok := p.loadVulnEvidenceFromCandidates(ciVulnEvidenceCandidates(req), req.Now); ok {
			return ciEvidence, nil
		}
	}
	return ensureVulnRawJSON(VulnerabilitySnapshot{
		Available:    false,
		SourceUsed:   VulnSourceUsedNone,
		Freshness:    FreshnessUnknown,
		FindingCount: 0,
		Details:      "no vulnerability evidence found (live check disabled or no cached/CI artifact present)",
	}, req.Now), nil
}

func executeGovulncheck(ctx context.Context, cwd string, run VulnerabilityScanner, now time.Time) (VulnerabilitySnapshot, error) {
	output, err := run(ctx, cwd)
	if err != nil {
		return VulnerabilitySnapshot{}, fmt.Errorf("govulncheck failed: %w", err)
	}
	count, parseErr := countGovulncheckFindings(output)
	if parseErr != nil {
		return VulnerabilitySnapshot{}, parseErr
	}
	normalized := vulnLiveReport{
		Source:       "local_live_check",
		GeneratedAt:  now.UTC().Format(time.RFC3339),
		FindingCount: count,
		Provenance:   vulnProvenance{Tool: "govulncheck", Mode: "live"},
		RawStream:    string(output),
	}
	raw, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return VulnerabilitySnapshot{}, fmt.Errorf("marshal vuln report: %w", err)
	}
	return VulnerabilitySnapshot{
		Available:    true,
		SourceUsed:   VulnSourceUsedLive,
		Freshness:    FreshnessLive,
		FindingCount: count,
		RawJSON:      append(raw, '\n'),
		Details:      "vulnerability evidence collected from live govulncheck run",
	}, nil
}

func countGovulncheckFindings(raw []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return count, nil
			}
			return 0, fmt.Errorf("parse govulncheck JSON stream: %w", err)
		}
		if _, ok := event["finding"]; ok {
			count++
		}
	}
}

func localVulnEvidenceCandidates(req Params) []string {
	return compactPaths(
		filepath.Join(req.OutDir, securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, ".stave", "cache", securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, securityaudit.ArtifactVulnReport),
	)
}

func ciVulnEvidenceCandidates(req Params) []string {
	return compactPaths(
		filepath.Join(req.Cwd, "artifacts", securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, "security", securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, "govulncheck.json"),
	)
}

func compactPaths(paths ...string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		if seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		out = append(out, cleaned)
	}
	return out
}

func (p DefaultVulnProvider) loadVulnEvidenceFromCandidates(candidates []string, now time.Time) (VulnerabilitySnapshot, bool) {
	for _, candidate := range candidates {
		raw, err := p.ReadFile(candidate)
		if err != nil {
			continue
		}
		count := inferVulnCount(raw)
		freshness := FreshnessCached
		if p.StatFile != nil {
			if stat, statErr := p.StatFile(candidate); statErr == nil {
				freshness = FreshnessFromTime(stat.ModTime())
			}
		}
		normalized := vulnArtifactWrapper{
			Source:       "artifact",
			Path:         candidate,
			FindingCount: count,
			LoadedAt:     now.UTC().Format(time.RFC3339),
			Raw:          json.RawMessage(raw),
		}
		payload, marshalErr := json.MarshalIndent(normalized, "", "  ")
		if marshalErr != nil {
			continue
		}
		source := VulnSourceUsedLocalCache
		if strings.Contains(candidate, "artifact") || strings.Contains(candidate, "govulncheck") {
			source = VulnSourceUsedCIArtifact
		}
		return ensureVulnRawJSON(VulnerabilitySnapshot{
			Available:    true,
			SourceUsed:   source,
			Freshness:    freshness,
			FindingCount: count,
			RawJSON:      append(payload, '\n'),
			Details:      fmt.Sprintf("loaded vulnerability evidence from %s", candidate),
		}, now), true
	}
	return VulnerabilitySnapshot{}, false
}

func ensureVulnRawJSON(in VulnerabilitySnapshot, now time.Time) VulnerabilitySnapshot {
	if len(in.RawJSON) > 0 {
		return in
	}
	payload := vulnFallbackEnvelope{
		Source:       in.SourceUsed,
		Available:    in.Available,
		Freshness:    in.Freshness,
		FindingCount: in.FindingCount,
		Details:      in.Details,
		GeneratedAt:  now.UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err == nil {
		in.RawJSON = append(raw, '\n')
	}
	return in
}

func inferVulnCount(raw []byte) int {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		if value, ok := obj["finding_count"]; ok {
			if count, ok := toInt(value); ok {
				return count
			}
		}
		if value, ok := obj["findings"]; ok {
			switch typed := value.(type) {
			case []any:
				return len(typed)
			}
		}
	}
	return bytes.Count(bytes.ToLower(raw), []byte(`"finding"`))
}

func toInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}
