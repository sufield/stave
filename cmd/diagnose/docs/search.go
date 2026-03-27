package docs

import (
	"context"
	"fmt"
	"io"
	"slices"
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
	Format        ui.OutputFormat
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
type SearchRunner struct {
	Stdout io.Writer
}

// NewSearchRunner initializes a runner with the provided output stream.
func NewSearchRunner(stdout io.Writer) *SearchRunner {
	return &SearchRunner{Stdout: stdout}
}

// Run executes the search and writes the results to the configured output.
func (r *SearchRunner) Run(ctx context.Context, req SearchRequest) error {
	if err := r.validate(req); err != nil {
		return err
	}

	files, err := collectDocsFiles(req.Root, req.Paths)
	if err != nil {
		return fmt.Errorf("collecting docs: %w", err)
	}
	if len(files) == 0 {
		return &ui.UserError{Err: fmt.Errorf("no documentation files found under %s", req.Root)}
	}

	hits, err := r.search(ctx, files, req)
	if err != nil {
		return err
	}

	total := len(hits)
	if total > req.MaxResults {
		hits = hits[:req.MaxResults]
	}

	res := SearchResult{
		Query:    req.Query,
		Total:    total,
		Returned: len(hits),
		Hits:     hits,
	}

	return r.report(res, req.Format)
}

func (r *SearchRunner) validate(req SearchRequest) error {
	if strings.TrimSpace(req.Query) == "" {
		return &ui.UserError{Err: fmt.Errorf("query cannot be empty")}
	}
	if req.MaxResults < 1 {
		return &ui.UserError{Err: fmt.Errorf("invalid --show %d: must be >= 1", req.MaxResults)}
	}
	return nil
}

func (r *SearchRunner) search(ctx context.Context, files []docsFile, req SearchRequest) ([]SearchHit, error) {
	tokens := tokenizeQuery(req.Query, req.CaseSensitive)
	phrase := strings.TrimSpace(req.Query)
	if !req.CaseSensitive {
		phrase = strings.ToLower(phrase)
	}

	var allHits []SearchHit
	for _, f := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hits, err := searchSingleFile(f, phrase, tokens, req.CaseSensitive)
		if err != nil {
			return nil, err
		}
		allHits = append(allHits, hits...)
	}

	slices.SortFunc(allHits, compareSearchHits)
	return allHits, nil
}

func (r *SearchRunner) report(res SearchResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	fmt.Fprintf(r.Stdout, "Query: %q\n", res.Query)
	if res.Total == 0 {
		fmt.Fprintln(r.Stdout, "No matches found.")
		return nil
	}

	fmt.Fprintf(r.Stdout, "Matches: %d\n\n", res.Total)
	for i, hit := range res.Hits {
		fmt.Fprintf(r.Stdout, "%d. [score=%d] %s:%d\n", i+1, hit.Score, hit.Path, hit.Line)
		fmt.Fprintf(r.Stdout, "   %s\n", hit.Snippet)
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
				Format:        fmtValue,
				CaseSensitive: caseSensitive,
			}

			return NewSearchRunner(cmd.OutOrStdout()).Run(cmd.Context(), req)
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
