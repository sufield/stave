package reporting

// --- Docs Search ---

type DocsSearchRequest struct {
	Query         string   `json:"query"`
	Root          string   `json:"root,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	MaxResults    int      `json:"max_results"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

type DocsSearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Snippet string `json:"snippet"`
}

type DocsSearchResponse struct {
	Query    string          `json:"query"`
	Total    int             `json:"total"`
	Returned int             `json:"returned"`
	Hits     []DocsSearchHit `json:"hits"`
}

// --- Docs Open ---

type DocsOpenRequest struct {
	Topic string   `json:"topic"`
	Root  string   `json:"root,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

type DocsOpenResponse struct {
	Topic   string `json:"topic"`
	Path    string `json:"path"`
	Match   string `json:"match"`
	Summary string `json:"summary"`
}
