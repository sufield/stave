package stave

import (
	"fmt"

	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
)

// ProfileSummary is one compliance profile's identity, as returned by
// [ListEmbeddedProfiles].
type ProfileSummary struct {
	ID   string
	Name string
}

// Profile is a validated compliance profile's summary, as returned by
// [LoadProfile]: identity plus requirement and control counts. Loading
// is also validation — a malformed file is returned as an error.
type Profile struct {
	ID               string
	Name             string
	RequirementCount int
	ControlCount     int
}

// ListEmbeddedProfiles returns the built-in compliance profiles
// (id + name) shipped with Stave. It is the library entry point behind
// `stave profile list`.
func ListEmbeddedProfiles() ([]ProfileSummary, error) {
	profiles, err := evidenceadapter.LoadEmbeddedProfiles()
	if err != nil {
		return nil, fmt.Errorf("load embedded profiles: %w", err)
	}
	out := make([]ProfileSummary, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, ProfileSummary{ID: p.ID, Name: p.Name})
	}
	return out, nil
}

// LoadProfile loads and validates a compliance-profile YAML file,
// returning its summary. It is the library entry point behind
// `stave profile validate`; a malformed profile is an error.
func LoadProfile(path string) (Profile, error) {
	p, err := evidenceadapter.LoadProfileFromFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("load profile: %w", err)
	}
	controls := 0
	for _, req := range p.Requirements {
		controls += len(req.ControlIDs)
	}
	return Profile{
		ID:               p.ID,
		Name:             p.Name,
		RequirementCount: len(p.Requirements),
		ControlCount:     controls,
	}, nil
}
