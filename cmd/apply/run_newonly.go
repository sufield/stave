package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/app/findingfilter"
	ui "github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// runNewOnlyOutput loads assessment history, classifies the current findings,
// and writes the filtered view showing only new, returned, and resolved findings.
func runNewOnlyOutput(ctx context.Context, stdout, _ io.Writer, opts *Options, results EvaluateResult) error {
	history, err := loadHistoryAssessments(ctx, opts.HistoryDir)
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}

	// Convert evaluation.Finding to remediation.Finding for the filter.
	currentFindings := make([]remediation.Finding, len(results.RawFindings))
	for i := range results.RawFindings {
		currentFindings[i] = remediation.Finding{Finding: results.RawFindings[i]}
	}

	var newSince time.Duration
	if opts.NewSince != "" {
		var parseErr error
		newSince, parseErr = parseDuration(opts.NewSince)
		if parseErr != nil {
			return fmt.Errorf("invalid --new-since value %q: %w", opts.NewSince, parseErr)
		}
	}

	// Treat a malformed --now as a hard error. The previous shape
	// silently fell back to time.Now() when parsing failed, which
	// hid typos and made test goldens diverge from production runs
	// without any signal. run_standard.go already errors on a bad
	// --now via compose.ResolveNow; align here so behavior is
	// uniform across apply modes.
	now, err := compose.ResolveNow(opts.NowTime)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	filterResult := findingfilter.Classify(findingfilter.Input{
		CurrentFindings: currentFindings,
		History:         history,
		NewSince:        newSince,
		Now:             now,
	})

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(filterResult)
	default:
		return writeNewOnlyText(stdout, filterResult)
	}
}

func writeNewOnlyText(w io.Writer, r *findingfilter.Result) error {
	fmt.Fprintln(w, "ASSESSMENT — NEW FINDINGS ONLY")
	fmt.Fprintf(w, "Filtered: %d chronic findings suppressed\n", r.SuppressedCount)
	fmt.Fprintf(w, "          %d new findings shown\n",
		len(r.NewFindings)+len(r.ReturnedFindings))
	fmt.Fprintln(w)

	if len(r.NewFindings) > 0 {
		fmt.Fprintf(w, "NEW THIS ASSESSMENT (%d)\n", len(r.NewFindings))
		for i := range r.NewFindings {
			f := &r.NewFindings[i]
			fmt.Fprintf(w, "  %-30s  %-8s  %s\n",
				f.Finding.ControlID,
				strings.ToUpper(f.Finding.ControlSeverity.String()),
				f.Finding.AssetID)
		}
		fmt.Fprintln(w)
	}

	if len(r.ReturnedFindings) > 0 {
		fmt.Fprintf(w, "RETURNED AFTER ABSENCE (%d)\n", len(r.ReturnedFindings))
		for i := range r.ReturnedFindings {
			f := &r.ReturnedFindings[i]
			fmt.Fprintf(w, "  %-30s  %-8s  %s\n",
				f.Finding.ControlID,
				strings.ToUpper(f.Finding.ControlSeverity.String()),
				f.Finding.AssetID)
			if f.LastSeen != nil {
				fmt.Fprintf(w, "    Previously seen: %s\n", f.LastSeen.Format("2006-01-02"))
			}
			if f.Cycles > 0 {
				fmt.Fprintf(w, "    Cycles: %d — investigate oscillation\n", f.Cycles)
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.ResolvedFindings) > 0 {
		fmt.Fprintf(w, "RECENTLY RESOLVED (%d) — fixed since last assessment\n", len(r.ResolvedFindings))
		for i := range r.ResolvedFindings {
			f := &r.ResolvedFindings[i]
			dwell := ""
			if f.DwellDays > 0 {
				dwell = fmt.Sprintf("  dwell: %dd", int(f.DwellDays))
			}
			fmt.Fprintf(w, "  %-30s  %-8s  resolved%s\n",
				f.ControlID, strings.ToUpper(f.Severity), dwell)
		}
		fmt.Fprintln(w)
	}

	if len(r.NewFindings) == 0 && len(r.ReturnedFindings) == 0 {
		fmt.Fprintln(w, "No new findings since last assessment.")
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Run without --new-only to see all %d findings.\n", r.TotalFindings)
	return nil
}

// loadHistoryAssessments loads all assessment JSON files from a directory.
func loadHistoryAssessments(ctx context.Context, dir string) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history directory: %w", err)
	}

	loader := artifact.NewLoader()
	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), loadErr)
			continue
		}
		assessments = append(assessments, a)
	}
	return assessments, nil
}

// parseDuration parses a human-friendly duration like "7d", "30d", or "168h".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if dayStr, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		s = dayStr
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
