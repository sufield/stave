package applycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/app/findingfilter"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// evaluateNewOnly classifies the current findings against assessment history
// and renders the new/returned/resolved view. Output replaces the standard
// report on stdout; warnings (skipped/misdirected history) cross as []string
// for the command to write to stderr. Gating is unchanged (computed from the
// same report in EvaluateStandard).
func evaluateNewOnly(ctx context.Context, req StandardRequest, report *evaluation.ComplianceReport, now time.Time) ([]byte, []string, error) {
	history, warnings, err := loadHistoryAssessments(ctx, req.HistoryDir)
	if err != nil {
		return nil, warnings, err
	}

	current := make([]remediation.Finding, len(report.Findings))
	for i := range report.Findings {
		current[i] = remediation.Finding{Finding: report.Findings[i]}
	}

	var newSince time.Duration
	if req.NewSince != "" {
		d, perr := parseDuration(req.NewSince)
		if perr != nil {
			return nil, warnings, fmt.Errorf("invalid --new-since value %q: %w: %w", req.NewSince, perr, ErrInvalidInput)
		}
		newSince = d
	}

	filterResult := findingfilter.Classify(findingfilter.Input{
		CurrentFindings: current,
		History:         history,
		NewSince:        newSince,
		EvalTime:        now,
	})

	var buf bytes.Buffer
	if err := renderNewOnly(req.Format, &buf, filterResult); err != nil {
		return nil, warnings, err
	}
	return buf.Bytes(), warnings, nil
}

// renderNewOnly renders the filter result as JSON or text.
func renderNewOnly(format string, w io.Writer, r *findingfilter.Result) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	return writeNewOnlyText(w, r)
}

// stickyWriter remembers the first write error so subsequent writes no-op.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = fmt.Errorf("write output: %w", err)
	}
	return n, s.err
}

func writeNewOnlyText(w io.Writer, r *findingfilter.Result) error {
	sw := &stickyWriter{w: w}
	fmt.Fprintln(sw, "ASSESSMENT — NEW FINDINGS ONLY")
	fmt.Fprintf(sw, "Filtered: %d chronic findings suppressed\n", r.SuppressedCount)
	fmt.Fprintf(sw, "          %d new findings shown\n", len(r.NewFindings)+len(r.ReturnedFindings))
	fmt.Fprintln(sw)

	if len(r.NewFindings) > 0 {
		fmt.Fprintf(sw, "NEW THIS ASSESSMENT (%d)\n", len(r.NewFindings))
		for i := range r.NewFindings {
			f := &r.NewFindings[i]
			fmt.Fprintf(sw, "  %-30s  %-8s  %s\n", f.Finding.ControlID, strings.ToUpper(f.Finding.SeverityLabel()), f.Finding.AssetID)
		}
		fmt.Fprintln(sw)
	}

	if len(r.ReturnedFindings) > 0 {
		fmt.Fprintf(sw, "RETURNED AFTER ABSENCE (%d)\n", len(r.ReturnedFindings))
		for i := range r.ReturnedFindings {
			f := &r.ReturnedFindings[i]
			fmt.Fprintf(sw, "  %-30s  %-8s  %s\n", f.Finding.ControlID, strings.ToUpper(f.Finding.SeverityLabel()), f.Finding.AssetID)
			if f.LastSeen != nil {
				fmt.Fprintf(sw, "    Previously seen: %s\n", f.LastSeen.Format("2006-01-02"))
			}
			if f.Cycles > 0 {
				fmt.Fprintf(sw, "    Cycles: %d — investigate oscillation\n", f.Cycles)
			}
		}
		fmt.Fprintln(sw)
	}

	if len(r.ResolvedFindings) > 0 {
		fmt.Fprintf(sw, "RECENTLY RESOLVED (%d) — fixed since last assessment\n", len(r.ResolvedFindings))
		for i := range r.ResolvedFindings {
			f := &r.ResolvedFindings[i]
			dwell := ""
			if f.DwellDays > 0 {
				dwell = fmt.Sprintf("  dwell: %dd", int(f.DwellDays))
			}
			fmt.Fprintf(sw, "  %-30s  %-8s  resolved%s\n", f.ControlID, strings.ToUpper(f.SeverityLabel()), dwell)
		}
		fmt.Fprintln(sw)
	}

	if len(r.NewFindings) == 0 && len(r.ReturnedFindings) == 0 {
		fmt.Fprintln(sw, "No new findings since last assessment.")
		fmt.Fprintln(sw)
	}

	fmt.Fprintf(sw, "Run without --new-only to see all %d findings.\n", r.TotalFindings)
	return sw.err
}

// loadHistoryAssessments loads all assessment JSON files from dir. An empty
// dir is a hard input error; skipped/misdirected-dir conditions return
// warnings (the command writes them to stderr).
func loadHistoryAssessments(ctx context.Context, dir string) ([]*report.Assessment, []string, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil, fmt.Errorf("--new-only / --new-since requires --history-dir; no history directory configured: %w", ErrInvalidInput)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read history directory: %w", err)
	}

	loader := artifact.NewLoader()
	var assessments []*report.Assessment
	var warnings []string
	candidateCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		candidateCount++
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			warnings = append(warnings, fmt.Sprintf("warning: skipping %s: %v", entry.Name(), loadErr))
			continue
		}
		assessments = append(assessments, a)
	}
	if candidateCount == 0 {
		warnings = append(warnings, fmt.Sprintf("warning: history directory %q contains no .json files; "+
			"check that --history-dir points at a directory of prior assessment outputs", dir))
	}
	return assessments, warnings, nil
}

// parseDuration parses a human-friendly duration like "7d", "30d", or "168h".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if dayStr, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(dayStr)
		if err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parse duration: %w", err)
	}
	return d, nil
}
