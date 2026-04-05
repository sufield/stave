package evidence

import "time"

// Params holds the subset of audit request fields that evidence collectors need.
type Params struct {
	Now                  time.Time
	Cwd                  string
	BinaryPath           string
	OutDir               string
	ComplianceFrameworks []string
	SBOMFormat           SBOMFormat
	VulnSource           VulnSource
	LiveVulnCheck        bool
	ReleaseBundleDir     string
	RequireOffline       bool
}
