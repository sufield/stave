package docs

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// searchDocsFiles runs a keyword search across all provided files.
func searchDocsFiles(ctx context.Context, files []docsFile, query string, caseSensitive bool) ([]SearchHit, error) {
	tokens, phrase := tokenizeQueryBytes(query, caseSensitive)

	var hits []SearchHit
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileHits, err := searchSingleFile(ctx, file, phrase, tokens, caseSensitive)
		if err != nil {
			return nil, err
		}
		hits = append(hits, fileHits...)
	}

	slices.SortFunc(hits, compareSearchHits)
	return hits, nil
}

func searchSingleFile(ctx context.Context, file docsFile, phrase []byte, tokens [][]byte, caseSensitive bool) ([]SearchHit, error) {
	// #nosec G304 -- path is discovered from directory walking.
	fh, err := os.Open(file.Abs)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", file.Abs, err)
	}
	defer fh.Close()
	return searchReader(ctx, fh, file.Rel, phrase, tokens, caseSensitive)
}

// searchReader runs keyword matching against an io.Reader, returning
// scored hits. Uses scanner.Bytes() to avoid per-line string allocation.
func searchReader(ctx context.Context, r io.Reader, relPath string, phrase []byte, tokens [][]byte, caseSensitive bool) ([]SearchHit, error) {
	pathBytes := []byte(relPath)
	if !caseSensitive {
		pathBytes = bytes.ToLower(pathBytes)
	}
	filePathScore := scorePath(pathBytes, tokens)

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var hits []SearchHit
	lineNo := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		lineNo++
		line := scanner.Bytes() // zero allocation
		score := scoreLine(line, phrase, tokens, caseSensitive) + filePathScore
		if score <= 0 {
			continue
		}
		// Only allocate a string when we actually find a hit.
		hits = append(hits, SearchHit{
			Path:    relPath,
			Line:    lineNo,
			Score:   score,
			Snippet: trimSnippet(string(line)),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", relPath, err)
	}
	return hits, nil
}

func compareSearchHits(a, b SearchHit) int {
	if n := cmp.Compare(b.Score, a.Score); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Path, b.Path); n != 0 {
		return n
	}
	return cmp.Compare(a.Line, b.Line)
}

// tokenizeQueryBytes prepares the search query as byte slices for
// zero-allocation matching in the scanner loop.
func tokenizeQueryBytes(query string, caseSensitive bool) ([][]byte, []byte) {
	phrase := []byte(strings.TrimSpace(query))
	if !caseSensitive {
		phrase = bytes.ToLower(phrase)
	}
	return bytes.Fields(phrase), phrase
}

func scorePath(path []byte, tokens [][]byte) int {
	score := 0
	for _, tok := range tokens {
		if bytes.Contains(path, tok) {
			score += 2
		}
	}
	return score
}

// scoreLine scores a line against the query tokens using byte operations
// to avoid string allocation in the hot path.
func scoreLine(line, phrase []byte, tokens [][]byte, caseSensitive bool) int {
	lineCmp := line
	if !caseSensitive {
		lineCmp = bytes.ToLower(line)
	}
	score := 0
	if len(phrase) > 0 && bytes.Contains(lineCmp, phrase) {
		score += 20
	}
	isHeader := bytes.HasPrefix(bytes.TrimLeft(line, " \t"), []byte("#"))
	matchedTokens := 0
	for _, tok := range tokens {
		count := bytes.Count(lineCmp, tok)
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
