package remediation

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

// TestBuildGroups_EmptyFingerprintDoesNotWarn is the regression for the
// noisy `remediation grouping: empty ActionsFingerprint; falling back
// to per-finding key` line that leaked to every user run at WARN. An
// empty fingerprint is a routine condition (a finding whose remediation
// plan has no hashable actions); the per-finding-key fallback handles
// it correctly and the operator has nothing to act on. It is an
// internal diagnostic that belongs at Debug (visible under -v), not a
// warning on a normal run.
func TestBuildGroups_EmptyFingerprintDoesNotWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	f := Finding{
		FindingID:       "f-1",
		ControlID:       "CTL.X.001",
		AssetID:         "asset-1",
		RemediationPlan: &evaluation.RemediationPlan{}, // empty ActionsFingerprint
	}
	groups := BuildGroups([]Finding{f})

	// Functional behavior is preserved: the finding still forms its own group.
	if len(groups) != 1 || groups[0].FindingCount != 1 {
		t.Fatalf("expected 1 group with 1 finding, got %d groups", len(groups))
	}

	sawFallback := false
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad log line: %v\n%s", err, line)
		}
		if rec["level"] == "WARN" {
			t.Errorf("empty-fingerprint fallback must not log at WARN: %s", line)
		}
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "empty ActionsFingerprint") {
			sawFallback = true
			if rec["level"] != "DEBUG" {
				t.Errorf("fallback should log at DEBUG, got level=%v", rec["level"])
			}
		}
	}
	if !sawFallback {
		t.Error("expected the fallback to still be logged (at debug) for diagnosability under -v")
	}
}
