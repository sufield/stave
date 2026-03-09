package docs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type docsSearchFlagsType struct {
	root          string
	paths         []string
	show          int
	format        string
	caseSensitive bool
}

type docsFile struct {
	Abs string
	Rel string
}

type docsSearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Snippet string `json:"snippet"`
}

type docsSearchOutput struct {
	Query    string          `json:"query"`
	Total    int             `json:"total"`
	Returned int             `json:"returned"`
	Hits     []docsSearchHit `json:"hits"`
}

type docsSearchRequest struct {
	query         string
	root          string
	paths         []string
	show          int
	format        ui.OutputFormat
	caseSensitive bool
}

// NewDocsSearchCmd constructs the docs search command with closure-scoped flags.
func NewDocsSearchCmd() *cobra.Command {
	var flags docsSearchFlagsType

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
			return runDocsSearch(cmd, args, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&flags.root, "docs-root", ".", "Directory to search from")
	cmd.Flags().StringSliceVar(&flags.paths, "path", []string{"README.md", "docs", "docs-content/cli-reference"}, "File or directory to include (repeatable)")
	cmd.Flags().IntVar(&flags.show, "show", 10, "Maximum number of results to print")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&flags.caseSensitive, "case-sensitive", false, "Use case-sensitive matching")

	return cmd
}

func runDocsSearch(cmd *cobra.Command, args []string, flags *docsSearchFlagsType) error {
	req, err := buildDocsSearchRequest(cmd, args, flags)
	if err != nil {
		return err
	}
	files, err := collectDocsFiles(req.root, req.paths)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no documentation files found under %s", req.root)
	}

	hits, err := searchDocsFiles(files, req.query, req.caseSensitive)
	if err != nil {
		return err
	}
	totalMatches := len(hits)

	if len(hits) > req.show {
		hits = hits[:req.show]
	}
	out := docsSearchOutput{
		Query:    req.query,
		Total:    totalMatches,
		Returned: len(hits),
		Hits:     hits,
	}

	if req.format.IsJSON() {
		return writeDocsSearchJSON(cmd.OutOrStdout(), out)
	}
	return writeDocsSearchText(cmd.OutOrStdout(), req.query, totalMatches, hits)
}

func buildDocsSearchRequest(cmd *cobra.Command, args []string, flags *docsSearchFlagsType) (docsSearchRequest, error) {
	if flags.show < 1 {
		return docsSearchRequest{}, fmt.Errorf("invalid --show %d: must be >= 1", flags.show)
	}
	query := strings.TrimSpace(strings.Join(args, " "))
	if query == "" {
		return docsSearchRequest{}, fmt.Errorf("query cannot be empty")
	}
	format, err := compose.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return docsSearchRequest{}, err
	}
	return docsSearchRequest{
		query:         query,
		root:          fsutil.CleanUserPath(flags.root),
		paths:         flags.paths,
		show:          flags.show,
		format:        format,
		caseSensitive: flags.caseSensitive,
	}, nil
}

func writeDocsSearchJSON(w io.Writer, out docsSearchOutput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeDocsSearchText(w io.Writer, query string, total int, hits []docsSearchHit) error {
	if _, err := fmt.Fprintf(w, "Query: %q\n", query); err != nil {
		return err
	}
	if total == 0 {
		_, err := fmt.Fprintln(w, "No matches found.")
		return err
	}
	if _, err := fmt.Fprintf(w, "Matches: %d\n\n", total); err != nil {
		return err
	}
	for i, hit := range hits {
		if _, err := fmt.Fprintf(w, "%d. [score=%d] %s:%d\n", i+1, hit.Score, hit.Path, hit.Line); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "   %s\n", hit.Snippet); err != nil {
			return err
		}
	}
	return nil
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
			continue
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
	sort.Slice(files, func(i, j int) bool {
		return files[i].Rel < files[j].Rel
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

func searchDocsFiles(files []docsFile, query string, caseSensitive bool) ([]docsSearchHit, error) {
	phrase := strings.TrimSpace(query)
	if !caseSensitive {
		phrase = strings.ToLower(phrase)
	}
	tokens := tokenizeQuery(query, caseSensitive)

	var hits []docsSearchHit
	for _, file := range files {
		fileHits, err := searchSingleFile(file, phrase, tokens, caseSensitive)
		if err != nil {
			return nil, err
		}
		hits = append(hits, fileHits...)
	}

	sortSearchHits(hits)
	return hits, nil
}

func searchSingleFile(file docsFile, phrase string, tokens []string, caseSensitive bool) ([]docsSearchHit, error) {
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

	var hits []docsSearchHit
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		score := scoreLine(line, phrase, tokens, caseSensitive) + filePathScore
		if score <= 0 {
			continue
		}
		hits = append(hits, docsSearchHit{
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

func sortSearchHits(hits []docsSearchHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Line < hits[j].Line
	})
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
