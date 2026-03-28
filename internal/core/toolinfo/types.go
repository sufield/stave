// Package toolinfo provides domain types and use cases for binary
// introspection: version, capabilities, schemas, and bug report.
package toolinfo

type VersionRequest struct {
	Verbose bool `json:"verbose,omitempty"`
}

type VersionResponse struct {
	VersionData any `json:"version_data"`
}

type CapabilitiesRequest struct{}

type CapabilitiesResponse struct {
	CapabilitiesData any `json:"capabilities_data"`
}

type SchemasRequest struct {
	Format string `json:"format,omitempty"`
}

type SchemasResponse struct {
	SchemasData any `json:"schemas_data"`
}

type BugReportRequest struct {
	OutPath       string `json:"out_path,omitempty"`
	TailLines     int    `json:"tail_lines"`
	IncludeConfig bool   `json:"include_config"`
}

type BugReportResponse struct {
	BundlePath string   `json:"bundle_path"`
	Warnings   []string `json:"warnings,omitempty"`
}

type BugReportInspectRequest struct {
	BundlePath string `json:"bundle_path"`
}

type BugReportInspectResponse struct {
	EntriesData any `json:"entries_data"`
}
