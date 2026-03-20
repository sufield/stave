package docs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

Examples:
  stave docs search "snapshot upcoming"
  stave docs search "fail on new violation" --format json
  stave docs search "I want to" --docs-root . --path docs --path README.md` + metadata.OfflineHelpSuffix,
		Args: cobra.MinimumNArgs(1),
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

// --- Shared Helpers (used by both SearchRunner and OpenRunner) ---

type docsFile struct {
	Abs string
	Rel string
}

func collectDocsFiles(root string, include []string) ([]docsFile, error) {
	root = fsutil.CleanUserPath(root)
	seen := make(map[string]struct{})
	var files []docsFile

	for _, rawPath := range include {
		includePath := strings.TrimSpace(rawPath)
		if includePath == "" {
			continue
		}
		full := fsutil.CleanUserPath(filepath.Join(root, includePath))
		info, err := os.Stat(full)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("cannot access %s: %w", includePath, err)
		}
		if info.Mode().IsRegular() {
			appendDocFileIfEligible(root, full, seen, &files)
			continue
		}
		if !info.IsDir() {
			continue
		}
		if err := appendDocsFromDirectory(root, full, seen, &files); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(files, func(a, b docsFile) int {
		return strings.Compare(a.Rel, b.Rel)
	})
	return files, nil
}

func appendDocFileIfEligible(root, abs string, seen map[string]struct{}, files *[]docsFile) {
	if !isDocFile(abs) {
		return
	}
	rel := relativeDocPath(root, abs)
	if _, ok := seen[rel]; ok {
		return
	}
	seen[rel] = struct{}{}
	*files = append(*files, docsFile{Abs: abs, Rel: rel})
}

func appendDocsFromDirectory(root, dir string, seen map[string]struct{}, files *[]docsFile) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		appendDocFileIfEligible(root, path, seen, files)
		return nil
	})
}

func relativeDocPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

func isDocFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".txt", ".rst", ".adoc":
		return true
	default:
		return false
	}
}

func searchDocsFiles(files []docsFile, query string, caseSensitive bool) ([]SearchHit, error) {
	phrase := strings.TrimSpace(query)
	if !caseSensitive {
		phrase = strings.ToLower(phrase)
	}
	tokens := tokenizeQuery(query, caseSensitive)

	var hits []SearchHit
	for _, file := range files {
		fileHits, err := searchSingleFile(file, phrase, tokens, caseSensitive)
		if err != nil {
			return nil, err
		}
		hits = append(hits, fileHits...)
	}

	slices.SortFunc(hits, compareSearchHits)
	return hits, nil
}

func searchSingleFile(file docsFile, phrase string, tokens []string, caseSensitive bool) ([]SearchHit, error) {
	pathCmp := file.Rel
	if !caseSensitive {
		pathCmp = strings.ToLower(pathCmp)
	}
	filePathScore := scorePath(pathCmp, tokens)

	fh, err := os.Open(file.Abs)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", file.Abs, err)
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var hits []SearchHit
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		score := scoreLine(line, phrase, tokens, caseSensitive) + filePathScore
		if score <= 0 {
			continue
		}
		hits = append(hits, SearchHit{
			Path:    file.Rel,
			Line:    lineNo,
			Score:   score,
			Snippet: trimSnippet(line),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", file.Abs, err)
	}
	return hits, nil
}

func compareSearchHits(a, b SearchHit) int {
	if a.Score != b.Score {
		return b.Score - a.Score
	}
	if a.Path != b.Path {
		return strings.Compare(a.Path, b.Path)
	}
	return a.Line - b.Line
}

func tokenizeQuery(query string, caseSensitive bool) []string {
	parts := strings.Fields(query)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !caseSensitive {
			p = strings.ToLower(p)
		}
		out = append(out, p)
	}
	return out
}

func scorePath(path string, tokens []string) int {
	score := 0
	for _, tok := range tokens {
		if strings.Contains(path, tok) {
			score += 2
		}
	}
	return score
}

func scoreLine(line, phrase string, tokens []string, caseSensitive bool) int {
	lineCmp := line
	if !caseSensitive {
		lineCmp = strings.ToLower(lineCmp)
	}
	score := 0
	if phrase != "" && strings.Contains(lineCmp, phrase) {
		score += 20
	}
	isHeader := strings.HasPrefix(strings.TrimLeft(line, " "), "#")
	matchedTokens := 0
	for _, tok := range tokens {
		count := strings.Count(lineCmp, tok)
		if count == 0 {
			continue
		}
		score += count * 3
		matchedTokens++
		if isHeader {
			score += 5
		}
	}
	if len(tokens) > 1 && matchedTokens == len(tokens) {
		score += 8
	}
	return score
}

func trimSnippet(s string) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) <= 160 {
		return s
	}
	return s[:157] + "..."
}
