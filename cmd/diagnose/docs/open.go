package docs

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var (
	docsOpenRoot   string
	docsOpenPaths  []string
	docsOpenFormat string
)

type docsOpenOutput struct {
	Topic   string `json:"topic"`
	Path    string `json:"path"`
	Match   string `json:"match"`
	Summary string `json:"summary"`
}

type docsOpenRequest struct {
	topic  string
	root   string
	paths  []string
	format ui.OutputFormat
}

var DocsOpenCmd = &cobra.Command{
	Use:   "open <topic>",
	Short: "Resolve a docs topic to one best-matching file path and summary",
	Long: `Open resolves a topic to the best local documentation page and prints the exact
file path plus a short summary in terminal output.

Examples:
  stave docs open "snapshot upcoming"
  stave docs open "ci gate policy" --format json` + metadata.OfflineHelpSuffix,
	Args:          cobra.MinimumNArgs(1),
	RunE:          runDocsOpen,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	DocsOpenCmd.Flags().StringVar(&docsOpenRoot, "docs-root", ".", "Directory to search from")
	DocsOpenCmd.Flags().StringSliceVar(&docsOpenPaths, "path", []string{"README.md", "docs", "docs-content/cli-reference"}, "File or directory to include (repeatable)")
	DocsOpenCmd.Flags().StringVarP(&docsOpenFormat, "format", "f", "text", "Output format: text or json")
}

func runDocsOpen(cmd *cobra.Command, args []string) error {
	req, err := resolveDocsOpenRequest(cmd, args)
	if err != nil {
		return err
	}
	out, err := buildDocsOpenOutput(req)
	if err != nil {
		return err
	}
	return writeDocsOpenOutput(cmd.OutOrStdout(), req.format, out)
}

func resolveDocsOpenRequest(cmd *cobra.Command, args []string) (docsOpenRequest, error) {
	topic := strings.TrimSpace(strings.Join(args, " "))
	if topic == "" {
		return docsOpenRequest{}, fmt.Errorf("topic cannot be empty")
	}
	format, err := cmdutil.ResolveFormatValue(cmd, docsOpenFormat)
	if err != nil {
		return docsOpenRequest{}, err
	}
	return docsOpenRequest{
		topic:  topic,
		root:   fsutil.CleanUserPath(docsOpenRoot),
		paths:  docsOpenPaths,
		format: format,
	}, nil
}

func buildDocsOpenOutput(req docsOpenRequest) (docsOpenOutput, error) {
	files, err := collectDocsFiles(req.root, req.paths)
	if err != nil {
		return docsOpenOutput{}, err
	}
	if len(files) == 0 {
		return docsOpenOutput{}, fmt.Errorf("no documentation files found under %s", req.root)
	}

	const searchCaseSensitive = false
	hits, err := searchDocsFiles(files, req.topic, searchCaseSensitive)
	if err != nil {
		return docsOpenOutput{}, err
	}
	if len(hits) == 0 {
		return docsOpenOutput{}, fmt.Errorf("no documentation topic match for %q; try `stave docs search %q`", req.topic, req.topic)
	}

	top := hits[0]
	absPath := resolveAbsPathForRel(files, top.Path)
	if absPath == "" {
		absPath = top.Path
	}
	return docsOpenOutput{
		Topic:   req.topic,
		Path:    absPath,
		Match:   fmt.Sprintf("%s:%d", top.Path, top.Line),
		Summary: resolveDocsOpenSummary(absPath, top.Line, top.Snippet),
	}, nil
}

func resolveDocsOpenSummary(absPath string, line int, fallback string) string {
	summary := summarizeDocAtMatch(absPath, line)
	if summary != "" {
		return summary
	}
	return fallback
}

func writeDocsOpenOutput(w io.Writer, format ui.OutputFormat, out docsOpenOutput) error {
	if format.IsJSON() {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	return writeDocsOpenText(w, out)
}

func writeDocsOpenText(w io.Writer, out docsOpenOutput) error {
	lines := []string{
		fmt.Sprintf("Topic: %q", out.Topic),
		fmt.Sprintf("Path: %s", out.Path),
		fmt.Sprintf("Match: %s", out.Match),
		fmt.Sprintf("Summary: %s", out.Summary),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func resolveAbsPathForRel(files []docsFile, rel string) string {
	for _, f := range files {
		if f.Rel == rel {
			return f.Abs
		}
	}
	return ""
}

func summarizeDocAtMatch(absPath string, line int) string {
	data, err := fsutil.ReadFileLimited(absPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if line < 1 {
		line = 1
	}
	idx := line - 1
	if idx >= len(lines) {
		idx = len(lines) - 1
	}
	for i := idx; i < len(lines) && i < idx+18; i++ {
		s := cleanDocSummaryLine(lines[i])
		if s != "" {
			return s
		}
	}
	for i := 0; i < len(lines) && i < 60; i++ {
		s := cleanDocSummaryLine(lines[i])
		if s != "" {
			return s
		}
	}
	return ""
}

func cleanDocSummaryLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "#") || strings.HasPrefix(s, "```") {
		return ""
	}
	if strings.HasPrefix(s, "|") || strings.HasPrefix(s, "---") {
		return ""
	}
	return trimSnippet(s)
}
