package setup

// --- Env List ---

type EnvListRequest struct {
	Format string `json:"format,omitempty"`
}

type EnvEntry struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Value        string `json:"value"`
	IsSet        bool   `json:"is_set"`
	DefaultValue string `json:"default_value,omitempty"`
}

type EnvListResponse struct {
	Entries []EnvEntry `json:"entries"`
}
