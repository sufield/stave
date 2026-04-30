package profile

import (
	"fmt"
	"sync"
)

// profilesMu guards the package-level registry. RegisterProfile is
// typically called from init() of profile-defining packages, but
// nothing prevents a runtime call (test setup, plugin load) from
// racing with AllProfiles / LoadProfile readers — guard explicitly
// rather than rely on init-time happens-before.
var (
	profilesMu sync.RWMutex
	profiles   = map[string]*Profile{}
)

// RegisterProfile adds a profile to the global registry.
func RegisterProfile(p *Profile) {
	profilesMu.Lock()
	defer profilesMu.Unlock()
	profiles[p.ID] = p
}

// LoadProfile returns a profile by ID or an error if not found.
func LoadProfile(id string) (*Profile, error) {
	profilesMu.RLock()
	defer profilesMu.RUnlock()
	p, ok := profiles[id]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", id)
	}
	return p, nil
}

// AllProfiles returns all registered profile IDs.
func AllProfiles() []string {
	profilesMu.RLock()
	defer profilesMu.RUnlock()
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	return ids
}
