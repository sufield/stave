package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type semanticDiffEngine struct{}

func (e *semanticDiffEngine) Name() string { return "semantic-diff" }

func (e *semanticDiffEngine) Run(ctx context.Context) (*EngineResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, "go", "run", "./internal/tools/semantic-diff")
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil {
		if strings.Contains(output, "DIVERGENCE") {
			return &EngineResult{
				Engine:       "semantic-diff",
				GapsFound:    parseDivergences(output),
				TotalChecked: countControls(output),
				Duration:     time.Since(start),
				DataSource:   "CEL vs Z3 differential",
			}, nil
		}
		return &EngineResult{
			Engine:   "semantic-diff",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("semantic-diff failed: %v\n%s", err, truncate(output, 500)),
		}, nil
	}

	controls := countControls(output)
	return &EngineResult{
		Engine:       "semantic-diff",
		Covered:      controls,
		TotalChecked: controls,
		Duration:     time.Since(start),
		DataSource:   "CEL vs Z3 differential",
	}, nil
}

func countDivergences(output string) int {
	return strings.Count(output, "DIVERGENCE")
}

func countControls(output string) int {
	n := 0
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "CTL.") && strings.Contains(line, "PASS") {
			n++
		}
		if strings.Contains(line, "CTL.") && strings.Contains(line, "DIVERGENCE") {
			n++
		}
	}
	if n == 0 {
		n = strings.Count(output, "CTL.")
	}
	return n
}

func parseDivergences(output string) []Gap {
	var gaps []Gap
	for line := range strings.SplitSeq(output, "\n") {
		if !strings.Contains(line, "DIVERGENCE") {
			continue
		}
		gaps = append(gaps, Gap{
			Service:     "stave-internal",
			Property:    strings.TrimSpace(line),
			Description: "CEL and Z3 evaluators disagree on this control",
			Severity:    "Critical",
			Taxonomy:    []string{"formal-semantics"},
			Source:      "semantic-diff",
			Confidence:  "High",
		})
	}
	return gaps
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
