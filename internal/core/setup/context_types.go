package setup

// --- Context ---

type ContextCreateRequest struct {
	Name            string `json:"name"`
	Dir             string `json:"dir,omitempty"`
	ConfigFile      string `json:"config_file,omitempty"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
}

type ContextCreateResponse struct {
	Name string `json:"name"`
}

type ContextListRequest struct {
	Format string `json:"format,omitempty"`
}

type ContextEntry struct {
	Name        string `json:"name"`
	ProjectRoot string `json:"project_root"`
	Active      bool   `json:"active,omitempty"`
}

type ContextListResponse struct {
	Entries []ContextEntry `json:"entries"`
}

type ContextUseRequest struct {
	Name string `json:"name"`
}

type ContextUseResponse struct {
	Name string `json:"name"`
}

type ContextShowRequest struct {
	Format string `json:"format,omitempty"`
}

type ContextShowResponse struct {
	Name        string `json:"name"`
	ProjectRoot string `json:"project_root"`
	SelectedBy  string `json:"selected_by"`
}

type ContextDeleteRequest struct {
	Name string `json:"name"`
}

type ContextDeleteResponse struct {
	Name string `json:"name"`
}
