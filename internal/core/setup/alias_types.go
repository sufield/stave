package setup

// --- Alias ---

type AliasSetRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type AliasSetResponse struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type AliasListRequest struct {
	Format string `json:"format,omitempty"`
}

type AliasEntry struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type AliasListResponse struct {
	Entries []AliasEntry `json:"entries"`
}

type AliasDeleteRequest struct {
	Name string `json:"name"`
}

type AliasDeleteResponse struct {
	Name string `json:"name"`
}
