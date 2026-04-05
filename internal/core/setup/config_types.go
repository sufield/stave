package setup

// --- Config Show ---

// ConfigShowRequest is the input for showing the full configuration.
type ConfigShowRequest struct {
	Format string `json:"format,omitempty"`
}

// ConfigShowResponse is the output of showing the configuration.
type ConfigShowResponse struct {
	ConfigData any `json:"config_data"`
}

// --- Config Get/Set/Delete ---

// ConfigGetRequest is the input for getting a single config value.
type ConfigGetRequest struct {
	Key string `json:"key"`
}

// ConfigGetResponse is the output of getting a config value.
type ConfigGetResponse struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

// ConfigSetRequest is the input for setting a config value.
type ConfigSetRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ConfigSetResponse is the output after setting a config value.
type ConfigSetResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ConfigDeleteRequest is the input for deleting a config key.
type ConfigDeleteRequest struct {
	Key string `json:"key"`
}

// ConfigDeleteResponse is the output after deleting a config key.
type ConfigDeleteResponse struct {
	Key string `json:"key"`
}
