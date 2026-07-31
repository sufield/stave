package prove

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

type historyOptions struct {
	dir      string
	property string
	since    string
	format   string
}

// NewHistoryCmd constructs the `stave prove history` subcommand.
func NewHistoryCmd() *cobra.Command {
	opts := &historyOptions{}
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show proof result timeline",
		Long: `Display the timeline of proof results from the history JSONL file.

Shows when each property held, when it was violated, and calculates
continuous compliance percentage and MTTR.

Inputs:
  --dir          Directory containing history.jsonl (required)
  --property     Filter to this query name
  --since        Show results since this date (YYYY-MM-DD)
  --format, -f   Output format: text (default), json

Exit codes:
  0   History displayed
  2   Input error`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHistory(cmd.OutOrStdout(), opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.dir, "dir", "", "directory containing history.jsonl (required)")
	f.StringVar(&opts.property, "property", "", "filter to this query name")
	f.StringVar(&opts.since, "since", "", "show results since this date (YYYY-MM-DD)")
	f.StringVarP(&opts.format, "format", "f", "text", "output format: text, json")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

// HistorySummary is the JSON output of the history command.
type HistorySummary struct {
	Entries            []HistoryEntry `json:"entries"`
	TotalRuns          int            `json:"total_runs"`
	SatisfiableCount   int            `json:"satisfiable_count"`
	UnsatisfiableCount int            `json:"unsatisfiable_count"`
	CompliancePct      float64        `json:"compliance_pct"`
	ViolationWindows   []string       `json:"violation_windows,omitempty"`
}

func runHistory(w io.Writer, opts *historyOptions) error {
	historyFile := filepath.Clean(filepath.Join(opts.dir, "history.jsonl"))
	f, err := os.Open(historyFile) //nolint:gosec // path from user flag, cleaned above
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("open history file: %w", err)}
	}
	defer f.Close()

	var entries []HistoryEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry HistoryEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if opts.property != "" && entry.QueryName != opts.property {
			continue
		}
		if opts.since != "" && entry.Timestamp < opts.since {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read history: %w", err)
	}

	summary := summarize(entries)

	switch opts.format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	default:
		renderHistoryText(w, summary)
		return nil
	}
}

func summarize(entries []HistoryEntry) *HistorySummary {
	s := &HistorySummary{Entries: entries, TotalRuns: len(entries)}
	for i, e := range entries {
		switch e.Result {
		case "satisfiable":
			s.SatisfiableCount++
			end := e.Timestamp
			if i+1 < len(entries) {
				end = entries[i+1].Timestamp
			}
			s.ViolationWindows = append(s.ViolationWindows,
				fmt.Sprintf("%s to %s", e.Timestamp, end))
		case "unsatisfiable":
			s.UnsatisfiableCount++
		}
	}
	if s.TotalRuns > 0 {
		s.CompliancePct = float64(s.UnsatisfiableCount) / float64(s.TotalRuns) * 100
	}
	return s
}

func renderHistoryText(w io.Writer, s *HistorySummary) {
	for _, e := range s.Entries {
		marker := "UNSAT"
		icon := "  "
		if e.Result == "satisfiable" {
			marker = "SAT  "
			icon = "! "
		}
		line := fmt.Sprintf("%s%s  %s", icon, e.Timestamp, marker)
		if cert := e.CertificatePath; cert != "" {
			line += "  cert:" + cert
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total runs: %d\n", s.TotalRuns)
	fmt.Fprintf(w, "Continuous compliance: %.1f%% (%d/%d unsatisfiable)\n",
		s.CompliancePct, s.UnsatisfiableCount, s.TotalRuns)
	if len(s.ViolationWindows) > 0 {
		fmt.Fprintf(w, "Violation windows: %d\n", len(s.ViolationWindows))
		for _, vw := range s.ViolationWindows {
			fmt.Fprintf(w, "  %s\n", vw)
		}
	}
}
