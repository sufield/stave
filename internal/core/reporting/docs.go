package reporting

import (
	"context"
	"fmt"
)

// DocsSearcherPort searches local documentation files.
type DocsSearcherPort interface {
	SearchDocs(ctx context.Context, req DocsSearchRequest) (DocsSearchResponse, error)
}

// DocsSearchDeps represents a docssearchdeps value.
type DocsSearchDeps struct {
	Searcher DocsSearcherPort
}

// DocsSearch searches local documentation files for keyword matches.
func DocsSearch(ctx context.Context, req DocsSearchRequest, deps DocsSearchDeps) (DocsSearchResponse, error) {
	if err := ctx.Err(); err != nil {
		return DocsSearchResponse{}, fmt.Errorf("docs-search: %w", err)
	}
	if req.Query == "" {
		return DocsSearchResponse{}, fmt.Errorf("docs-search: query cannot be empty")
	}
	if req.MaxResults < 1 {
		return DocsSearchResponse{}, fmt.Errorf("docs-search: max-results must be >= 1")
	}
	resp, err := deps.Searcher.SearchDocs(ctx, req)
	if err != nil {
		return DocsSearchResponse{}, fmt.Errorf("docs-search: %w", err)
	}
	return resp, nil
}

// DocsOpenerPort resolves a documentation topic to its best match.
type DocsOpenerPort interface {
	OpenDoc(ctx context.Context, req DocsOpenRequest) (DocsOpenResponse, error)
}

// DocsOpenDeps represents a docsopendeps value.
type DocsOpenDeps struct {
	Opener DocsOpenerPort
}

// DocsOpen resolves a documentation topic to the best-matching file.
func DocsOpen(ctx context.Context, req DocsOpenRequest, deps DocsOpenDeps) (DocsOpenResponse, error) {
	if err := ctx.Err(); err != nil {
		return DocsOpenResponse{}, fmt.Errorf("docs-open: %w", err)
	}
	if req.Topic == "" {
		return DocsOpenResponse{}, fmt.Errorf("docs-open: topic cannot be empty")
	}
	resp, err := deps.Opener.OpenDoc(ctx, req)
	if err != nil {
		return DocsOpenResponse{}, fmt.Errorf("docs-open: %w", err)
	}
	return resp, nil
}

// --- Docs Search Types ---

// DocsSearchRequest represents a docssearchrequest value.
type DocsSearchRequest struct {
	Query         string   `json:"query"`
	Root          string   `json:"root,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	MaxResults    int      `json:"max_results"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

// DocsSearchHit represents a docssearchhit value.
type DocsSearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Snippet string `json:"snippet"`
}

// DocsSearchResponse represents a docssearchresponse value.
type DocsSearchResponse struct {
	Query    string          `json:"query"`
	Total    int             `json:"total"`
	Returned int             `json:"returned"`
	Hits     []DocsSearchHit `json:"hits"`
}

// --- Docs Open Types ---

// DocsOpenRequest represents a docsopenrequest value.
type DocsOpenRequest struct {
	Topic string   `json:"topic"`
	Root  string   `json:"root,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

// DocsOpenResponse represents a docsopenresponse value.
type DocsOpenResponse struct {
	Topic   string `json:"topic"`
	Path    string `json:"path"`
	Match   string `json:"match"`
	Summary string `json:"summary"`
}
