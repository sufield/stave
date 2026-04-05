package setup

// --- Alias ---

// AliasSetRequest is the input for creating or updating a command alias.
type AliasSetRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// AliasSetResponse is the output after setting an alias.
type AliasSetResponse struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// AliasListRequest is the input for listing aliases.
type AliasListRequest struct {
	Format string `json:"format,omitempty"`
}

// AliasEntry represents a single alias in a list response.
type AliasEntry struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// AliasListResponse is the output of listing aliases.
type AliasListResponse struct {
	Entries []AliasEntry `json:"entries"`
}

// AliasDeleteRequest is the input for deleting an alias.
type AliasDeleteRequest struct {
	Name string `json:"name"`
}

// AliasDeleteResponse is the output after deleting an alias.
type AliasDeleteResponse struct {
	Name string `json:"name"`
}
