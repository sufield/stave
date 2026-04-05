package setup

// --- Status ---

type StatusRequest struct {
	Dir string `json:"dir,omitempty"`
}

type StatusResponse struct {
	StateData   any    `json:"state_data"`
	NextCommand string `json:"next_command,omitempty"`
}
