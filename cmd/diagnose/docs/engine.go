package docs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// searchDocsFiles runs a keyword search across all provided files.
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
	// #nosec G304 -- path is discovered from directory walking.
	fh, err := os.Open(file.Abs)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", file.Abs, err)
	}
	defer fh.Close()
	return searchReader(fh, file.Rel, phrase, tokens, caseSensitive)
}

// searchReader runs keyword matching against an io.Reader, returning
// scored hits. Separated from file I/O for testability.
func searchReader(r io.Reader, relPath string, phrase string, tokens []string, caseSensitive bool) ([]SearchHit, error) {
	pathCmp := relPath
	if !caseSensitive {
		pathCmp = strings.ToLower(pathCmp)
	}
	filePathScore := scorePath(pathCmp, tokens)

	scanner := bufio.NewScanner(r)
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
			Path:    relPath,
			Line:    lineNo,
			Score:   score,
			Snippet: trimSnippet(line),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", relPath, err)
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
