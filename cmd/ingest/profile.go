package ingest

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// IngestProfile represents a validated ingest/extraction profile name.
type IngestProfile string

const (
	// ProfileAWSS3 selects the AWS S3 extraction profile.
	ProfileAWSS3 IngestProfile = "aws-s3"
)

// ParseProfile validates and returns an IngestProfile value.
func ParseProfile(s string) (IngestProfile, error) {
	switch IngestProfile(s) {
	case ProfileAWSS3:
		return ProfileAWSS3, nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: aws-s3)", s)
	}
}

// ProfileInfo describes an available ingest profile and its data requirements.
type ProfileInfo struct {
	Name        IngestProfile      `json:"name"`
	Description string             `json:"description"`
	Inputs      []InputRequirement `json:"inputs"`
}

// InputRequirement describes a single file or directory expected by the profile.
type InputRequirement struct {
	Path        string `json:"path"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// AllProfiles returns the registry of supported ingestion strategies.
func AllProfiles() []ProfileInfo {
	return []ProfileInfo{
		{
			Name:        ProfileAWSS3,
			Description: "Extract S3 bucket observations from AWS CLI JSON snapshots",
			Inputs: []InputRequirement{
				{Path: "list-buckets.json", Required: true, Description: "aws s3api list-buckets"},
				{Path: "get-bucket-tagging/<bucket>.json", Required: false, Description: "aws s3api get-bucket-tagging"},
				{Path: "get-bucket-policy/<bucket>.json", Required: false, Description: "aws s3api get-bucket-policy"},
				{Path: "get-bucket-acl/<bucket>.json", Required: false, Description: "aws s3api get-bucket-acl"},
				{Path: "get-public-access-block/<bucket>.json", Required: false, Description: "aws s3api get-public-access-block"},
			},
		},
	}
}

// --- Presentation Logic ---

// RegistryPresenter handles the visual representation of the profile registry.
type RegistryPresenter struct {
	Stdout io.Writer
}

// RenderText outputs the profile registry in a human-readable table format.
func (p *RegistryPresenter) RenderText() error {
	profiles := AllProfiles()

	for i, profile := range profiles {
		if i > 0 {
			fmt.Fprintln(p.Stdout)
		}

		fmt.Fprintf(p.Stdout, "Profile: %s\n", profile.Name)
		fmt.Fprintf(p.Stdout, "Description: %s\n\n", profile.Description)
		fmt.Fprintln(p.Stdout, "  Expected inputs (inside the --input directory):")

		tw := tabwriter.NewWriter(p.Stdout, 0, 8, 2, ' ', 0)
		for _, inp := range profile.Inputs {
			reqStr := "(optional)"
			if inp.Required {
				reqStr = "(required)"
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", inp.Path, reqStr, inp.Description)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}
