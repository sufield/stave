package profile

import (
	"fmt"
	"slices"
	"sync"
)

// profileRegistry is the concurrency-safe set of registered profiles. Bundling
// the map with the RWMutex that guards it keeps the lock and the data it
// protects in one type; nothing can read or mutate the registry without going
// through a method. RegisterProfile is typically called from init() of
// profile-defining packages, but a runtime call (test setup, plugin load) could
// race with AllProfiles / LoadProfile readers, so access is guarded explicitly
// rather than relying on init-time happens-before.
type profileRegistry struct {
	mu       sync.RWMutex
	profiles map[ProfileID]*Profile
}

// register adds p, panicking on a nil/empty-ID profile or a duplicate ID (see
// RegisterProfile for why a panic is the right startup-time failure mode).
func (r *profileRegistry) register(p *Profile) {
	if p == nil || p.ID == "" {
		panic("profile: RegisterProfile called with nil profile or empty ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.profiles[p.ID]; exists {
		panic(fmt.Sprintf("profile %q registered twice; check init() order across profile packages", p.ID))
	}
	r.profiles[p.ID] = p
}

// load returns a deep copy of the profile registered under id, or false.
func (r *profileRegistry) load(id ProfileID) (*Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[id]
	if !ok {
		return nil, false
	}
	return p.Clone(), true
}

// allIDs returns every registered profile ID in stable sorted order.
func (r *profileRegistry) allIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	return ids
}

// registry is the process-wide profile registry — one cohesive instance rather
// than a loose mutex+map pair.
var registry = &profileRegistry{profiles: map[ProfileID]*Profile{}}

// RegisterProfile adds a profile to the global registry. Panics on
// duplicate IDs: a duplicate registration is almost always two
// init() functions claiming the same id, which silently let the
// later loser overwrite the earlier registration in unspecified
// order. Naming the conflict at registration time turns a flaky
// "wrong profile loaded" symptom into a deterministic startup
// failure.
func RegisterProfile(p *Profile) {
	registry.register(p)
}

// LoadProfile returns a profile by ID or an error if not found.
// Accepts a string for CLI ergonomics — runs ParseProfileID at the
// boundary so a malformed ID surfaces as a "invalid profile ID"
// error rather than a generic "unknown profile" miss.
func LoadProfile(id string) (*Profile, error) {
	parsed, err := ParseProfileID(id)
	if err != nil {
		return nil, err
	}
	p, ok := registry.load(parsed)
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", id)
	}
	return p, nil
}

// Clone returns a deep copy of the profile so a caller mutating the
// returned handle (changing Name, appending to Controls, swapping
// a Control element's Severity) cannot corrupt the shared registry
// slot the next LoadProfile caller will read. Encapsulates the
// "Profiles are immutable once registered" contract on the type
// itself; LoadProfile delegates here so the immutability rule
// lives next to the data definition.
//
// The Controls slice is freshly allocated. Each element is copied
// and the SeverityOverride pointer is reallocated so a caller
// mutating *cp.Controls[i].SeverityOverride cannot reach back into
// the registry's stored Profile through a shared pointer.
// Extending Control with additional pointer / slice / map fields
// requires extending Clone in lockstep.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Controls = make([]Control, len(p.Controls))
	for i, ctl := range p.Controls {
		cp.Controls[i] = ctl
		if ctl.SeverityOverride != nil {
			sev := *ctl.SeverityOverride
			cp.Controls[i].SeverityOverride = &sev
		}
	}
	return &cp
}

// AllProfiles returns all registered profile IDs in stable sorted
// order. Map iteration is randomized, so the earlier shape produced
// a different ordering across runs — fine for set-membership
// callers, broken for any consumer that diffed the list (CLI help
// text, test goldens, generated docs). Sorting locks the order in.
func AllProfiles() []string {
	return registry.allIDs()
}
