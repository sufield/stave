package profile

import "fmt"

var profiles = map[string]*Profile{}

// RegisterProfile adds a profile to the global registry.
func RegisterProfile(p *Profile) {
	profiles[p.ID] = p
}

// LoadProfile returns a profile by ID or an error if not found.
func LoadProfile(id string) (*Profile, error) {
	p, ok := profiles[id]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", id)
	}
	return p, nil
}

// AllProfiles returns all registered profile IDs.
func AllProfiles() []string {
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	return ids
}
