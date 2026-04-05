package setup

// --- Config Show ---

type ConfigShowRequest struct {
	Format string `json:"format,omitempty"`
}

type ConfigShowResponse struct {
	ConfigData any `json:"config_data"`
}

// --- Config Get/Set/Delete ---

type ConfigGetRequest struct {
	Key string `json:"key"`
}

type ConfigGetResponse struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

type ConfigSetRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ConfigSetResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ConfigDeleteRequest struct {
	Key string `json:"key"`
}

type ConfigDeleteResponse struct {
	Key string `json:"key"`
}
