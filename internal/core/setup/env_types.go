package setup

// --- Env List ---

// EnvListRequest is the input for listing environment variables.
type EnvListRequest struct {
	Format string `json:"format,omitempty"`
}

// EnvEntry represents a single environment variable in a list response.
type EnvEntry struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Value        string `json:"value"`
	IsSet        bool   `json:"is_set"`
	DefaultValue string `json:"default_value,omitempty"`
}

// EnvListResponse is the output of listing environment variables.
type EnvListResponse struct {
	Entries []EnvEntry `json:"entries"`
}
