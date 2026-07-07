package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Write_DuplicateChainMetrics(t *testing.T) {
	// A report with the same chain activated on two different assets.
	// In the original code, the output formats `stave_chain_active{chain="CHAIN.1",severity="critical"} 1`
	// twice without asset/scope labels, creating duplicate metric lines with identical label sets.
	// This violates the Prometheus exposition format specification.
	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment: &report.Assessment{
			Run: evaluation.RunInfo{EvalTime: time.Now()},
			ChainFindings: []findings.CompoundFinding{
				{
					ChainID:  "CHAIN.1",
					AssetID:  "asset-a",
					Severity: policy.SeverityCritical,
				},
				{
					ChainID:  "CHAIN.1",
					AssetID:  "asset-b",
					Severity: policy.SeverityCritical,
				},
			},
		},
	})

	output := buf.String()
	lines := strings.Split(output, "\n")
	seen := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if seen[trimmed] {
			t.Errorf("Prometheus exporter produced duplicate metric line: %q", trimmed)
		}
		seen[trimmed] = true
	}
}
