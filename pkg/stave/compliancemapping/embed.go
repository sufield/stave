package compliancemapping

import "embed"

//go:embed data/*.json
var dataFS embed.FS

// frameworkFiles maps a public framework name to its embedded mapping file.
// Add a new framework by dropping its mapping JSON in data/ and a line here.
var frameworkFiles = map[string]string{
	"aicm-v1.1": "aicm-v1.1.json",
}

// SupportedFrameworks returns the framework names this build can evaluate.
func SupportedFrameworks() string {
	// ponytail: one framework today; join-on-demand when a second lands.
	return "aicm-v1.1"
}
