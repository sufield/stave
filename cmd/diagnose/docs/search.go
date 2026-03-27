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

// SearchRequest defines the parameters for a documentation search.
type SearchRequest struct {
	Query         string
	Root          string
	Paths         []string
	MaxResults    int
	CaseSensitive bool
}

// SearchHit represents a single keyword match in a document.
type SearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Snippet string `json:"snippet"`
}

// SearchResult is the structured output of a search operation.
type SearchResult struct {
	Query    string      `json:"query"`
	Total    int         `json:"total"`
	Returned int         `json:"returned"`
	Hits     []SearchHit `json:"hits"`
}

// SearchRunner orchestrates the documentation search process.
type SearchRunner struct{}

// Run executes the search and returns the result.
// Presentation is handled by the caller.
func (r *SearchRunner) Run(ctx context.Context, req SearchRequest) (SearchResult, error) {
	if err := validateSearchRequest(req); err != nil {
		return SearchResult{}, err
	}

	files, err := collectDocsFiles(req.Root, req.Paths)
	if err != nil {
		return SearchResult{}, fmt.Errorf("collecting docs: %w", err)
	}
	if len(files) == 0 {
		return SearchResult{}, &ui.UserError{Err: fmt.Errorf("no documentation files found under %s", req.Root)}
	}

	hits, err := searchDocsFiles(ctx, files, req.Query, req.CaseSensitive)
	if err != nil {
		return SearchResult{}, err
	}

	total := len(hits)
	if total > req.MaxResults {
		hits = hits[:req.MaxResults]
	}

	return SearchResult{
		Query:    req.Query,
		Total:    total,
		Returned: len(hits),
		Hits:     hits,
	}, nil
}

func validateSearchRequest(req SearchRequest) error {
	if strings.TrimSpace(req.Query) == "" {
		return &ui.UserError{Err: fmt.Errorf("query cannot be empty")}
	}
	if req.MaxResults < 1 {
		return &ui.UserError{Err: fmt.Errorf("invalid --show %d: must be >= 1", req.MaxResults)}
	}
	return nil
}

// writeSearchResult renders a SearchResult to the writer in the given format.
func writeSearchResult(w io.Writer, res SearchResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, res)
	}

	fmt.Fprintf(w, "Query: %q\n", res.Query)
	if res.Total == 0 {
		fmt.Fprintln(w, "No matches found.")
		return nil
	}

	fmt.Fprintf(w, "Matches: %d\n\n", res.Total)
	for i, hit := range res.Hits {
		fmt.Fprintf(w, "%d. [score=%d] %s:%d\n", i+1, hit.Score, hit.Path, hit.Line)
		fmt.Fprintf(w, "   %s\n", hit.Snippet)
	}
	return nil
}

// --- Cobra Command Constructor ---

// NewDocsSearchCmd constructs the docs search command with closure-scoped flags.
func NewDocsSearchCmd() *cobra.Command {
	var (
		root          string
		paths         []string
		show          int
		format        string
		caseSensitive bool
	)

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search local Stave documentation from the terminal",
		Long: `Search inspects local documentation files and returns ranked keyword matches.
It is offline-only and deterministic, so it can run in CI and air-gapped workflows.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave docs search "snapshot upcoming" --format json`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}

			req := SearchRequest{
				Query:         strings.Join(args, " "),
				Root:          fsutil.CleanUserPath(root),
				Paths:         paths,
				MaxResults:    show,
				CaseSensitive: caseSensitive,
			}

			runner := &SearchRunner{}
			result, err := runner.Run(cmd.Context(), req)
			if err != nil {
				return err
			}
			return writeSearchResult(cmd.OutOrStdout(), result, fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&root, "docs-root", ".", "Directory to search from")
	cmd.Flags().StringSliceVar(&paths, "path", []string{"README.md", "docs", "docs-content/cli-reference"}, "File or directory to include (repeatable)")
	cmd.Flags().IntVar(&show, "show", 10, "Maximum number of results to print")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&caseSensitive, "case-sensitive", false, "Use case-sensitive matching")

	return cmd
}
