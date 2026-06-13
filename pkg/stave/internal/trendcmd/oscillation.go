package trendcmd

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// OscillationConfig parameterizes [ClassifyOscillation].
type OscillationConfig struct {
	HistoryDir      string
	Files           string
	MinOscillations int
	Format          string
}

// ClassifyOscillation classifies control-asset pairs into oscillation
// patterns (chronic / deploy-time / random) across the assessment history and
// renders the results (table | json). Returns the rendered bytes + load
// warnings. An unknown format wraps [InputError] (exit 2); other failures
// stay plain (exit 4). It is the library entry point behind
// `stave trend oscillation`.
func ClassifyOscillation(ctx context.Context, cfg OscillationConfig) ([]byte, []string, error) {
	if cfg.HistoryDir == "" && cfg.Files == "" {
		return nil, nil, errors.New("either --history or --files is required")
	}
	assessments, warnings, err := loadAssessments(ctx, cfg.HistoryDir, cfg.Files)
	if err != nil {
		return nil, warnings, err
	}
	if len(assessments) < 2 {
		return nil, warnings, fmt.Errorf("oscillation analysis requires at least 2 assessment files (found %d)", len(assessments))
	}

	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	vals := make([]report.Assessment, len(assessments))
	for i, a := range assessments {
		vals[i] = *a
	}

	type fkey struct{ ctl, ast string }
	pairs := make(map[fkey]bool)
	for i := range vals {
		for j := range vals[i].Findings {
			f := &vals[i].Findings[j]
			pairs[fkey{string(f.ControlID), string(f.AssetID)}] = true
		}
	}

	var results []oscillation.Classification
	for k := range pairs {
		c := oscillation.Classify(oscillation.Input{
			Assessments:     vals,
			ControlID:       kernel.ControlID(k.ctl),
			AssetID:         k.ast,
			MinOscillations: cfg.MinOscillations,
		})
		if c.Pattern != "" {
			results = append(results, c)
		}
	}

	slices.SortFunc(results, func(a, b oscillation.Classification) int {
		if a.Pattern != b.Pattern {
			return cmp.Compare(a.Pattern, b.Pattern)
		}
		if a.ControlID != b.ControlID {
			return cmp.Compare(a.ControlID, b.ControlID)
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})

	var buf bytes.Buffer
	if rErr := renderOscillation(cfg.Format, &buf, results); rErr != nil {
		return nil, warnings, rErr
	}
	return buf.Bytes(), warnings, nil
}

func writeOscillationTable(w io.Writer, results []oscillation.Classification) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No oscillation patterns detected.")
		return
	}

	fmt.Fprintln(w, "OSCILLATION ANALYSIS")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "%-14s %-30s %-30s %6s %5s %s\n",
		"Pattern", "Control", "Asset", "Fail%", "Cycles", "Confidence")
	fmt.Fprintf(w, "%-14s %-30s %-30s %6s %5s %s\n",
		strings.Repeat("-", 14), strings.Repeat("-", 30), strings.Repeat("-", 30),
		strings.Repeat("-", 6), strings.Repeat("-", 5), strings.Repeat("-", 10))

	for i := range results {
		r := &results[i]
		fmt.Fprintf(w, "%-14s %-30s %-30s %5.0f%% %5d %.2f\n",
			r.Pattern, truncate(r.ControlID, 30), truncate(r.AssetID, 30),
			r.FailureRate*100, r.Cycles, r.Confidence)
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit-3] + "..."
}
