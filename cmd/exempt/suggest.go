package exempt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
	"github.com/sufield/stave/internal/core/report"
)

func newSuggestCmd() *cobra.Command {
	var historyDir, window, minDwell, format, file string

	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Suggest exemptions for chronic/oscillating findings",
		Long: `Analyze assessment history to identify findings that have been open
long enough to warrant a formal governance decision: fix, formally
accept the risk, or escalate.

Oscillating findings (fixed then returned) are separated from chronic
findings (continuously open). Each includes a copy-paste exemption command.

Exit Codes:
  0   Suggestions produced
  2   Invalid input`,
		Example: `  stave exempt suggest --history ./history --window 30d --min-dwell 14d
  stave exempt suggest --history ./history --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSuggest(cmd.Context(), cmd.OutOrStdout(), historyDir, window, minDwell, format, file)
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "directory of historical assessment JSON files (required)")
	cmd.Flags().StringVar(&window, "window", "30d", "how far back to look for patterns (e.g. 30d, 90d)")
	cmd.Flags().StringVar(&minDwell, "min-dwell", "14d", "minimum time a finding must be open to be chronic (e.g. 14d)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file (for excluding already-exempted findings)")
	_ = cmd.MarkFlagRequired("history")

	return cmd
}

func runSuggest(ctx context.Context, w io.Writer, historyDir, windowStr, minDwellStr, format, acceptanceFile string) error {
	windowDur, err := parseSuggestDuration(windowStr)
	if err != nil {
		return fmt.Errorf("invalid --window: %w", err)
	}
	minDwellDur, err := parseSuggestDuration(minDwellStr)
	if err != nil {
		return fmt.Errorf("invalid --min-dwell: %w", err)
	}

	history, err := loadSuggestHistory(ctx, historyDir)
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}

	if len(history) == 0 {
		fmt.Fprintln(w, "No assessment history found.")
		return nil
	}

	// Load existing exemptions to exclude already-handled findings.
	exemptedKeys := make(map[string]bool)
	if acceptanceFile != "" {
		af, loadErr := appexempt.Load(acceptanceFile)
		if loadErr == nil {
			for i := range af.Acknowledgments {
				if af.Acknowledgments[i].Status == "active" {
					exemptedKeys[af.Acknowledgments[i].ID] = true
				}
			}
			for i := range af.Exceptions {
				key := af.Exceptions[i].ControlID + "@" + af.Exceptions[i].AssetID
				exemptedKeys[key] = true
			}
		}
	}

	result := exemptionsuggest.Suggest(exemptionsuggest.Input{
		History:      history,
		Window:       windowDur,
		MinDwell:     minDwellDur,
		Now:          time.Now().UTC(),
		ExemptedKeys: exemptedKeys,
	})

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		return writeSuggestTable(w, result)
	}
}

func writeSuggestTable(w io.Writer, r *exemptionsuggest.Result) error {
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
				strings.ToUpper(c.Severity),
				c.AssetID)
			fmt.Fprintf(w, "    Cycles: %d in %d days\n", c.Cycles, r.WindowDays)
			if c.OwnerTeamID != "" {
				fmt.Fprintf(w, "    Team: %s\n", c.OwnerTeamID)
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
			if c.OwnerTeamID != "" {
				team = "  Team " + c.OwnerTeamID
			}
			fmt.Fprintf(w, "  %-30s  %-8s  open %dd%s\n",
				c.ControlID,
				strings.ToUpper(c.Severity),
				int(c.DwellDays),
				team)
			fmt.Fprintf(w, "    Command: %s\n", c.ExemptCmd)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func loadSuggestHistory(ctx context.Context, dir string) ([]*report.Assessment, error) {
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

func parseSuggestDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if dayStr, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		if _, err := fmt.Sscanf(dayStr, "%d", &days); err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
