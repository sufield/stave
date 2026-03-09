package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/securityaudit"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// GovulncheckRunner executes govulncheck and returns its combined output.
// The concrete implementation lives in the adapter layer (internal/adapters/govulncheck/).
type GovulncheckRunner func(ctx context.Context, cwd string) ([]byte, error)

type defaultVulnEvidenceProvider struct {
	runGovulncheck GovulncheckRunner
}

func (p defaultVulnEvidenceProvider) Resolve(ctx context.Context, req SecurityAuditRequest) (vulnerabilitySnapshot, error) {
	if shouldAttemptLiveCheck(req) {
		live, liveErr := executeGovulncheck(ctx, req.Cwd, p.runGovulncheck, req.Now)
		if liveErr == nil {
			return ensureVulnRawJSON(live, req.Now), nil
		}
		// Keep fallback behavior but preserve the live-check failure reason.
		fallback, err := resolveVulnFallback(req)
		if err == nil && fallback.Available {
			fallback.Details = fmt.Sprintf("live check failed (%v); used fallback evidence", liveErr)
			return ensureVulnRawJSON(fallback, req.Now), nil
		}
		return ensureVulnRawJSON(vulnerabilitySnapshot{
			Available:    false,
			SourceUsed:   "live_check_failed",
			Freshness:    "unknown",
			FindingCount: 0,
			Details:      fmt.Sprintf("govulncheck execution failed: %v", liveErr),
		}, req.Now), nil
	}
	fallback, err := resolveVulnFallback(req)
	if err != nil {
		return vulnerabilitySnapshot{}, err
	}
	return ensureVulnRawJSON(fallback, req.Now), nil
}

func shouldAttemptLiveCheck(req SecurityAuditRequest) bool {
	if !req.LiveVulnCheck {
		return false
	}
	return req.VulnSource == VulnSourceLocal || req.VulnSource == VulnSourceHybrid
}

func resolveVulnFallback(req SecurityAuditRequest) (vulnerabilitySnapshot, error) {
	if req.VulnSource == VulnSourceLocal || req.VulnSource == VulnSourceHybrid {
		if cached, ok := loadVulnEvidenceFromCandidates(localVulnEvidenceCandidates(req), req.Now); ok {
			return cached, nil
		}
	}
	if req.VulnSource == VulnSourceCI || req.VulnSource == VulnSourceHybrid {
		if ciEvidence, ok := loadVulnEvidenceFromCandidates(ciVulnEvidenceCandidates(req), req.Now); ok {
			return ciEvidence, nil
		}
	}
	return ensureVulnRawJSON(vulnerabilitySnapshot{
		Available:    false,
		SourceUsed:   "none",
		Freshness:    "unknown",
		FindingCount: 0,
		Details:      "no vulnerability evidence found (live check disabled or no cached/CI artifact present)",
	}, req.Now), nil
}

func executeGovulncheck(ctx context.Context, cwd string, run GovulncheckRunner, now time.Time) (vulnerabilitySnapshot, error) {
	output, err := run(ctx, cwd)
	if err != nil {
		return vulnerabilitySnapshot{}, fmt.Errorf("govulncheck failed: %w", err)
	}
	count, parseErr := countGovulncheckFindings(output)
	if parseErr != nil {
		return vulnerabilitySnapshot{}, parseErr
	}
	normalized := map[string]any{
		"source":        "local_live_check",
		"generated_at":  now.UTC().Format(time.RFC3339),
		"finding_count": count,
		"provenance": map[string]any{
			"tool": "govulncheck",
			"mode": "live",
		},
		"raw_stream": string(output),
	}
	raw, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return vulnerabilitySnapshot{}, fmt.Errorf("marshal vuln report: %w", err)
	}
	return vulnerabilitySnapshot{
		Available:    true,
		SourceUsed:   "local_live_check",
		Freshness:    "live",
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

func localVulnEvidenceCandidates(req SecurityAuditRequest) []string {
	return compactPaths(
		filepath.Join(req.OutDir, securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, ".stave", "cache", securityaudit.ArtifactVulnReport),
		filepath.Join(req.Cwd, securityaudit.ArtifactVulnReport),
	)
}

func ciVulnEvidenceCandidates(req SecurityAuditRequest) []string {
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

func loadVulnEvidenceFromCandidates(candidates []string, now time.Time) (vulnerabilitySnapshot, bool) {
	for _, candidate := range candidates {
		raw, err := fsutil.ReadFileLimited(candidate)
		if err != nil {
			continue
		}
		count := inferVulnCount(raw)
		freshness := "cached"
		if stat, statErr := os.Stat(candidate); statErr == nil {
			freshness = stat.ModTime().UTC().Format(time.RFC3339)
		}
		normalized := map[string]any{
			"source":        "artifact",
			"path":          candidate,
			"finding_count": count,
			"loaded_at":     now.UTC().Format(time.RFC3339),
			"raw":           json.RawMessage(raw),
		}
		payload, marshalErr := json.MarshalIndent(normalized, "", "  ")
		if marshalErr != nil {
			continue
		}
		source := "local_cache"
		if strings.Contains(candidate, "artifact") || strings.Contains(candidate, "govulncheck") {
			source = "ci_artifact"
		}
		return ensureVulnRawJSON(vulnerabilitySnapshot{
			Available:    true,
			SourceUsed:   source,
			Freshness:    freshness,
			FindingCount: count,
			RawJSON:      append(payload, '\n'),
			Details:      fmt.Sprintf("loaded vulnerability evidence from %s", candidate),
		}, now), true
	}
	return vulnerabilitySnapshot{}, false
}

func ensureVulnRawJSON(in vulnerabilitySnapshot, now time.Time) vulnerabilitySnapshot {
	if len(in.RawJSON) > 0 {
		return in
	}
	payload := map[string]any{
		"source":        in.SourceUsed,
		"available":     in.Available,
		"freshness":     in.Freshness,
		"finding_count": in.FindingCount,
		"details":       in.Details,
		"generated_at":  now.UTC().Format(time.RFC3339),
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
