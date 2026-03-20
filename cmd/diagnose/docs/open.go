package docs

import (
	"context"
	"fmt"
	"io"
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
	Format        ui.OutputFormat
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
type OpenRunner struct {
	Stdout io.Writer
}

// NewOpenRunner initializes a runner with the provided output stream.
func NewOpenRunner(stdout io.Writer) *OpenRunner {
	return &OpenRunner{Stdout: stdout}
}

// Run resolves the topic and writes the result to the configured output.
func (r *OpenRunner) Run(_ context.Context, req OpenRequest) error {
	if strings.TrimSpace(req.Topic) == "" {
		return fmt.Errorf("topic cannot be empty")
	}

	files, err := collectDocsFiles(req.Root, req.Paths)
	if err != nil {
		return fmt.Errorf("collecting docs: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no documentation files found under %s", req.Root)
	}

	hits, err := searchDocsFiles(files, req.Topic, req.CaseSensitive)
	if err != nil {
		return err
	}
	if len(hits) == 0 {
		return fmt.Errorf("no documentation topic match for %q; try `stave docs search %q`", req.Topic, req.Topic)
	}

	top := hits[0]
	absPath := r.resolveAbsPath(files, top.Path)

	result := OpenResult{
		Topic:   req.Topic,
		Path:    absPath,
		Match:   fmt.Sprintf("%s:%d", top.Path, top.Line),
		Summary: r.summarizeAtMatch(absPath, top.Line, top.Snippet),
	}

	return r.write(result, req.Format)
}

func (r *OpenRunner) resolveAbsPath(files []docsFile, rel string) string {
	for _, f := range files {
		if f.Rel == rel {
			return f.Abs
		}
	}
	return rel
}

func (r *OpenRunner) summarizeAtMatch(absPath string, line int, fallback string) string {
	data, err := fsutil.ReadFileLimited(absPath)
	if err != nil {
		return fallback
	}

	lines := strings.Split(string(data), "\n")
	idx := max(line-1, 0)
	if idx >= len(lines) {
		idx = len(lines) - 1
	}

	for i := idx; i < len(lines) && i < idx+18; i++ {
		if s := r.cleanLine(lines[i]); s != "" {
			return s
		}
	}

	for i := 0; i < len(lines) && i < 60; i++ {
		if s := r.cleanLine(lines[i]); s != "" {
			return s
		}
	}
	return fallback
}

func (r *OpenRunner) cleanLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "```") ||
		strings.HasPrefix(s, "|") || strings.HasPrefix(s, "---") {
		return ""
	}
	return trimSnippet(s)
}

func (r *OpenRunner) write(res OpenResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	fmt.Fprintf(r.Stdout, "Topic: %q\n", res.Topic)
	fmt.Fprintf(r.Stdout, "Path: %s\n", res.Path)
	fmt.Fprintf(r.Stdout, "Match: %s\n", res.Match)
	fmt.Fprintf(r.Stdout, "Summary: %s\n", res.Summary)
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

Examples:
  stave docs open "snapshot upcoming"
  stave docs open "ci gate policy" --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}

			req := OpenRequest{
				Topic:  strings.Join(args, " "),
				Root:   fsutil.CleanUserPath(root),
				Paths:  paths,
				Format: fmtValue,
			}

			return NewOpenRunner(cmd.OutOrStdout()).Run(cmd.Context(), req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&root, "docs-root", ".", "Directory to search from")
	cmd.Flags().StringSliceVar(&paths, "path", []string{"README.md", "docs", "docs-content/cli-reference"}, "File or directory to include (repeatable)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
