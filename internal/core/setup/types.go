// Package setup provides request/response types and use case orchestration
// for project setup and configuration: init with profile scaffolding,
// doctor environment checks, status with next-command recommendation,
// config get/set/delete/show, command alias management, named context
// management, environment variable listing, and control/observation
// template generation.
package setup

import "github.com/sufield/stave/internal/core/outcome"

// --- Doctor ---

type DoctorRequest struct {
	Cwd        string `json:"cwd,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Format     string `json:"format,omitempty"`
}

type DoctorResponse struct {
	Checks    []DoctorCheck `json:"checks"`
	AllPassed bool          `json:"all_passed"`
}

type DoctorCheck struct {
	Name    string         `json:"name"`
	Status  outcome.Status `json:"status"`
	Message string         `json:"message,omitempty"`
	Fix     string         `json:"fix,omitempty"`
}

// --- Config Show ---

type ConfigShowRequest struct {
	Format string `json:"format,omitempty"`
}

type ConfigShowResponse struct {
	ConfigData any `json:"config_data"`
}

// --- Status ---

type StatusRequest struct {
	Dir string `json:"dir,omitempty"`
}

type StatusResponse struct {
	StateData   any    `json:"state_data"`
	NextCommand string `json:"next_command,omitempty"`
}

// --- Generate Control ---

type GenerateControlRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

type GenerateControlResponse struct {
	OutputPath string `json:"output_path"`
}

// --- Generate Observation ---

type GenerateObservationRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

type GenerateObservationResponse struct {
	OutputPath string `json:"output_path"`
}

// --- Init Project ---

type InitRequest struct {
	Dir               string `json:"dir,omitempty"`
	Profile           string `json:"profile,omitempty"`
	DryRun            bool   `json:"dry_run,omitempty"`
	WithGitHubActions bool   `json:"with_github_actions,omitempty"`
	CaptureCadence    string `json:"capture_cadence,omitempty"`
	Force             bool   `json:"force,omitempty"`
}

type InitResponse struct {
	BaseDir string   `json:"base_dir"`
	Dirs    []string `json:"dirs"`
	Created []string `json:"created"`
	Skipped []string `json:"skipped,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
}

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
