package docs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// OpenRequest defines the parameters for resolving a documentation topic.
type OpenRequest struct {
	Topic         string
	Root          string
	Paths         []string
	CaseSensitive bool
}

// OpenResult represents the best-matching documentation hit.
type OpenResult struct {
	Topic   string `json:"topic"`
	Path    string `json:"path"`
	Match   string `json:"match"`
	Summary string `json:"summary"`
}

// OpenRunner orchestrates the discovery and resolution of documentation topics.
type OpenRunner struct{}

// Run resolves the topic and returns the best-matching result.
// Presentation is handled by the caller.
func (r *OpenRunner) Run(ctx context.Context, req OpenRequest) (OpenResult, error) {
	if strings.TrimSpace(req.Topic) == "" {
		return OpenResult{}, fmt.Errorf("topic cannot be empty")
	}

	files, err := collectDocsFiles(req.Root, req.Paths)
	if err != nil {
		return OpenResult{}, fmt.Errorf("collecting docs: %w", err)
	}
	if len(files) == 0 {
		return OpenResult{}, fmt.Errorf("no documentation files found under %s", req.Root)
	}

	hits, err := searchDocsFiles(ctx, files, req.Topic, req.CaseSensitive)
	if err != nil {
		return OpenResult{}, err
	}
	if len(hits) == 0 {
		return OpenResult{}, fmt.Errorf("no documentation topic match for %q; try `stave docs search %q`", req.Topic, req.Topic)
	}

	top := hits[0]
	absPath := resolveAbsPath(files, top.Path)

	return OpenResult{
		Topic:   req.Topic,
		Path:    absPath,
		Match:   fmt.Sprintf("%s:%d", top.Path, top.Line),
		Summary: summarizeAtMatch(absPath, top.Line, top.Snippet),
	}, nil
}

func resolveAbsPath(files []docsFile, rel string) string {
	for _, f := range files {
		if f.Rel == rel {
			return f.Abs
		}
	}
	return rel
}

// summarizeAtMatch streams the file up to the target line using a scanner
// instead of loading the entire file into memory.
func summarizeAtMatch(absPath string, targetLine int, fallback string) string {
	// #nosec G304 -- path is from directory walking.
	f, err := os.Open(absPath)
	if err != nil {
		return fallback
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	startLine := max(targetLine, 1)

	// Scan to the target line and check up to 18 lines after it.
	for scanner.Scan() {
		lineNo++
		if lineNo < startLine {
			continue
		}
		if lineNo >= startLine+18 {
			break
		}
		if s := cleanLine(scanner.Text()); s != "" {
			return s
		}
	}
	return fallback
}

// cleanLine returns a trimmed line suitable for a summary, or empty string
// if the line is a header, code fence, table, or horizontal rule.
func cleanLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "```") ||
		strings.HasPrefix(s, "|") || strings.HasPrefix(s, "---") {
		return ""
	}
	return trimSnippet(s)
}

// writeOpenResult renders an OpenResult to the writer in the given format.
func writeOpenResult(w io.Writer, res OpenResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, res)
	}
	fmt.Fprintf(w, "Topic: %q\n", res.Topic)
	fmt.Fprintf(w, "Path: %s\n", res.Path)
	fmt.Fprintf(w, "Match: %s\n", res.Match)
	fmt.Fprintf(w, "Summary: %s\n", res.Summary)
	return nil
}

// --- Cobra Command Constructor ---

// NewDocsOpenCmd constructs the docs open command with closure-scoped flags.
func NewDocsOpenCmd() *cobra.Command {
	var (
		root   string
		paths  []string
		format string
	)

	cmd := &cobra.Command{
		Use:   "open <topic>",
		Short: "Resolve a docs topic to one best-matching file path and summary",
		Long: `Open resolves a topic to the best local documentation page and prints the exact
file path plus a short summary in terminal output.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave docs open "snapshot upcoming"`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}

			req := OpenRequest{
				Topic: strings.Join(args, " "),
				Root:  fsutil.CleanUserPath(root),
				Paths: paths,
			}

			runner := &OpenRunner{}
			result, err := runner.Run(cmd.Context(), req)
			if err != nil {
				return err
			}
			return writeOpenResult(cmd.OutOrStdout(), result, fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&root, "docs-root", ".", "Directory to search from")
	cmd.Flags().StringSliceVar(&paths, "path", []string{"README.md", "docs", "docs-content/cli-reference"}, "File or directory to include (repeatable)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
