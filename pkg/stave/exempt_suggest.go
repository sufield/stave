package stave

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
	"github.com/sufield/stave/internal/core/report"
)

// SuggestConfig parameterizes [SuggestExemptions]. Window and MinDwell are
// raw duration strings (e.g. "30d", "14d", or standard Go durations).
type SuggestConfig struct {
	HistoryDir     string
	Window         string
	MinDwell       string
	Format         string
	AcceptanceFile string
}

// SuggestExemptions analyzes assessment history to identify chronic /
// oscillating findings that warrant a formal governance decision, excluding
// already-exempted findings from the acceptance file, and renders the
// candidates (table | json). A missing/empty history renders an explanatory
// message. It is the library entry point behind `stave exempt suggest`.
func SuggestExemptions(ctx context.Context, cfg SuggestConfig) ([]byte, error) {
	window, err := exemptParseSuggestDuration(cfg.Window)
	if err != nil {
		return nil, fmt.Errorf("invalid --window: %w", err)
	}
	minDwell, err := exemptParseSuggestDuration(cfg.MinDwell)
	if err != nil {
		return nil, fmt.Errorf("invalid --min-dwell: %w", err)
	}

	history, err := exemptLoadSuggestHistory(ctx, cfg.HistoryDir)
	if err != nil {
		return nil, fmt.Errorf("load history: %w", err)
	}

	var result *exemptionsuggest.Result
	if len(history) > 0 {
		exemptedKeys := exemptCollectKeys(cfg.AcceptanceFile)
		result = exemptionsuggest.Suggest(exemptionsuggest.Input{
			History:      history,
			Window:       window,
			MinDwell:     minDwell,
			EvalTime:     time.Now().UTC(),
			ExemptedKeys: exemptedKeys,
		})
	}

	var buf bytes.Buffer
	if result == nil {
		if _, werr := fmt.Fprintln(&buf, "No assessment history found."); werr != nil {
			return nil, fmt.Errorf("write output: %w", werr)
		}
		return buf.Bytes(), nil
	}
	renderer, err := exemptNewSuggestRenderer(cfg.Format)
	if err != nil {
		return nil, err
	}
	if rerr := renderer.Render(&buf, result); rerr != nil {
		return nil, fmt.Errorf("render output: %w", rerr)
	}
	return buf.Bytes(), nil
}

func exemptWriteSuggestTable(w io.Writer, r *exemptionsuggest.Result) error {
	fmt.Fprintln(w, "EXEMPTION CANDIDATES")
	fmt.Fprintf(w, "History: %d days  |  Min dwell: %d days\n\n", r.WindowDays, r.MinDwellDays)

	if len(r.Oscillating) == 0 && len(r.Chronic) == 0 {
		fmt.Fprintln(w, "No findings meet the threshold for exemption suggestion.")
		return nil
	}

	fmt.Fprintln(w, "These findings have been open without exemption for")
	fmt.Fprintln(w, "longer than your threshold. Each requires a decision:")
	fmt.Fprintln(w, "fix it, formally accept the risk, or escalate.")
	fmt.Fprintln(w)

	if len(r.Oscillating) > 0 {
		fmt.Fprintf(w, "OSCILLATING — root cause required, not re-remediation (%d)\n", len(r.Oscillating))
		for i := range r.Oscillating {
			c := &r.Oscillating[i]
			fmt.Fprintf(w, "  %-30s  %-8s  %s\n",
				c.ControlID,
				strings.ToUpper(c.Severity.String()),
				c.AssetID)
			fmt.Fprintf(w, "    Cycles: %d in %d days\n", c.Cycles, r.WindowDays)
			if c.HasOwner() {
				fmt.Fprintf(w, "    Team: %s\n", c.OwnerKey())
			}
			fmt.Fprintf(w, "    Command: %s\n", c.ExemptCmd)
		}
		fmt.Fprintln(w)
	}

	if len(r.Chronic) > 0 {
		fmt.Fprintf(w, "CHRONIC — open >%dd, no exemption (%d)\n", r.MinDwellDays, len(r.Chronic))
		for i := range r.Chronic {
			c := &r.Chronic[i]
			team := ""
			if c.HasOwner() {
				team = "  Team " + c.OwnerKey()
			}
			fmt.Fprintf(w, "  %-30s  %-8s  open %dd%s\n",
				c.ControlID,
				strings.ToUpper(c.Severity.String()),
				int(c.DwellDays),
				team)
			fmt.Fprintf(w, "    Command: %s\n", c.ExemptCmd)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func exemptCollectKeys(acceptanceFile string) map[string]struct{} {
	keys := make(map[string]struct{})
	if acceptanceFile == "" {
		return keys
	}
	af, loadErr := appexempt.Load(acceptanceFile)
	if loadErr != nil {
		return keys
	}
	for i := range af.Acknowledgments {
		if af.Acknowledgments[i].IsActive() {
			keys[af.Acknowledgments[i].ID] = struct{}{}
		}
	}
	nowUTC := time.Now().UTC()
	nowDate := time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), 0, 0, 0, 0, time.UTC)
	for i := range af.Exceptions {
		exc := &af.Exceptions[i]
		if exc.ExpiryDate != "" {
			expiry, parseErr := time.Parse("2006-01-02", exc.ExpiryDate)
			if parseErr == nil && expiry.Before(nowDate) {
				continue
			}
		}
		keys[string(exc.ControlID)+"@"+exc.AssetID] = struct{}{}
	}
	return keys
}

func exemptLoadSuggestHistory(ctx context.Context, dir string) ([]*report.Assessment, error) {
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

func exemptParseSuggestDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if dayStr, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		if _, err := fmt.Sscanf(dayStr, "%d", &days); err != nil {
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
