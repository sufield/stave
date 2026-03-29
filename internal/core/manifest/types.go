// Package manifest provides request/response types and use case orchestration
// for observation integrity manifests: generate unsigned manifests, sign
// with Ed25519 private keys, and generate signing keypairs.
package manifest

// --- Generate ---

type GenerateRequest struct {
	ObservationsDir string `json:"observations_dir"`
	OutPath         string `json:"out_path,omitempty"`
}

type GenerateResponse struct {
	OutputPath   string `json:"output_path"`
	FileCount    int    `json:"file_count"`
	SkippedCount int    `json:"skipped_count,omitempty"`
}

// --- Sign ---

type SignRequest struct {
	InPath         string `json:"in_path"`
	PrivateKeyPath string `json:"private_key_path"`
	OutPath        string `json:"out_path,omitempty"`
}

type SignResponse struct {
	OutputPath string `json:"output_path"`
}

// --- Keygen ---

type KeygenRequest struct {
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	PublicKeyPath  string `json:"public_key_path,omitempty"`
}

type KeygenResponse struct {
	PrivateKeyPath string `json:"private_key_path"`
	PublicKeyPath  string `json:"public_key_path"`
}
