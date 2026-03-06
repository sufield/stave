package ingest

import (
	"fmt"
	"io"
)

// ingestProfile represents a validated ingest/extraction profile name.
type ingestProfile string

const (
	// ingestProfileMVP1S3 selects the MVP 1.0 S3 extraction profile.
	ingestProfileMVP1S3 ingestProfile = "mvp1-s3"
)

// parseIngestProfile validates and returns an ingestProfile value.
func parseIngestProfile(s string) (ingestProfile, error) {
	switch ingestProfile(s) {
	case ingestProfileMVP1S3:
		return ingestProfileMVP1S3, nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: mvp1-s3)", s)
	}
}

// IngestProfileInfo describes an available ingest profile for --list-profiles.
type IngestProfileInfo struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Inputs      []IngestProfileInput `json:"inputs"`
}

// IngestProfileInput describes a single expected input for an ingest profile.
type IngestProfileInput struct {
	Path        string `json:"path"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// ingestProfiles is the static registry of available ingest profiles.
var ingestProfiles = []IngestProfileInfo{
	{
		Name:        "mvp1-s3",
		Description: "Extract S3 bucket observations from AWS CLI JSON snapshots",
		Inputs: []IngestProfileInput{
			{Path: "list-buckets.json", Required: true, Description: "aws s3api list-buckets"},
			{Path: "get-bucket-tagging/<bucket>.json", Required: false, Description: "aws s3api get-bucket-tagging"},
			{Path: "get-bucket-policy/<bucket>.json", Required: false, Description: "aws s3api get-bucket-policy"},
			{Path: "get-bucket-acl/<bucket>.json", Required: false, Description: "aws s3api get-bucket-acl"},
			{Path: "get-public-access-block/<bucket>.json", Required: false, Description: "aws s3api get-public-access-block"},
		},
	},
}

// printIngestProfiles renders the profile registry as human-readable text.
func printIngestProfiles(w io.Writer) {
	for i, p := range ingestProfiles {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  %s\n", p.Name, p.Description)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Expected inputs (in --input directory):")
		for _, inp := range p.Inputs {
			req := "(optional)"
			if inp.Required {
				req = "(required)"
			}
			fmt.Fprintf(w, "    %-44s %s  %s\n", inp.Path, req, inp.Description)
		}
	}
}
