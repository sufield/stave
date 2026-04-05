package setup

// --- Context ---

// ContextCreateRequest is the input for creating a named context.
type ContextCreateRequest struct {
	Name            string `json:"name"`
	Dir             string `json:"dir,omitempty"`
	ConfigFile      string `json:"config_file,omitempty"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
}

// ContextCreateResponse is the output after creating a context.
type ContextCreateResponse struct {
	Name string `json:"name"`
}

// ContextListRequest is the input for listing contexts.
type ContextListRequest struct {
	Format string `json:"format,omitempty"`
}

// ContextEntry represents a single context in a list response.
type ContextEntry struct {
	Name        string `json:"name"`
	ProjectRoot string `json:"project_root"`
	Active      bool   `json:"active,omitempty"`
}

// ContextListResponse is the output of listing contexts.
type ContextListResponse struct {
	Entries []ContextEntry `json:"entries"`
}

// ContextUseRequest is the input for activating a context.
type ContextUseRequest struct {
	Name string `json:"name"`
}

// ContextUseResponse is the output after activating a context.
type ContextUseResponse struct {
	Name string `json:"name"`
}

// ContextShowRequest is the input for showing the active context.
type ContextShowRequest struct {
	Format string `json:"format,omitempty"`
}

// ContextShowResponse is the output of showing the active context.
type ContextShowResponse struct {
	Name        string `json:"name"`
	ProjectRoot string `json:"project_root"`
	SelectedBy  string `json:"selected_by"`
}

// ContextDeleteRequest is the input for deleting a context.
type ContextDeleteRequest struct {
	Name string `json:"name"`
}

// ContextDeleteResponse is the output after deleting a context.
type ContextDeleteResponse struct {
	Name string `json:"name"`
}
