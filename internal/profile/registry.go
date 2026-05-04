package profile

import (
	"fmt"
	"slices"
	"sync"
)

// profilesMu guards the package-level registry. RegisterProfile is
// typically called from init() of profile-defining packages, but
// nothing prevents a runtime call (test setup, plugin load) from
// racing with AllProfiles / LoadProfile readers — guard explicitly
// rather than rely on init-time happens-before.
var (
	profilesMu sync.RWMutex
	profiles   = map[ProfileID]*Profile{}
)

// RegisterProfile adds a profile to the global registry. Panics on
// duplicate IDs: a duplicate registration is almost always two
// init() functions claiming the same id, which silently let the
// later loser overwrite the earlier registration in unspecified
// order. Naming the conflict at registration time turns a flaky
// "wrong profile loaded" symptom into a deterministic startup
// failure.
func RegisterProfile(p *Profile) {
	// Guard against nil / empty-ID profiles before touching the
	// registry. A nil pointer would NPE on profiles[p.ID]; an
	// empty ID would cause every later registration with no ID
	// to clobber the same map slot. RegisterProfile is called
	// from init() so a panic is the right failure mode — the
	// startup-time crash names the offender.
	if p == nil || p.ID == "" {
		panic("profile: RegisterProfile called with nil profile or empty ID")
	}
	profilesMu.Lock()
	defer profilesMu.Unlock()
	if _, exists := profiles[p.ID]; exists {
		panic(fmt.Sprintf("profile %q registered twice; check init() order across profile packages", p.ID))
	}
	profiles[p.ID] = p
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
	profilesMu.RLock()
	defer profilesMu.RUnlock()
	p, ok := profiles[parsed]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", id)
	}
	return p.Clone(), nil
}

// Clone returns a deep copy of the profile so a caller mutating the
// returned handle (changing Name, appending to Controls, swapping
// a Control element's Severity) cannot corrupt the shared registry
// slot the next LoadProfile caller will read. Encapsulates the
// "Profiles are immutable once registered" contract on the type
// itself; LoadProfile delegates here so the immutability rule
// lives next to the data definition.
//
// The Controls slice is freshly allocated; Control elements are
// shallow-copied. The current Control shape (ControlID +
// ComplianceRef + Rationale + *Severity) carries no caller-mutable
// slice/map fields, so a shallow element copy is sufficient.
// Extending Control with mutable slice/map fields requires
// extending Clone in lockstep.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Controls = append([]Control(nil), p.Controls...)
	return &cp
}

// AllProfiles returns all registered profile IDs in stable sorted
// order. Map iteration is randomized, so the earlier shape produced
// a different ordering across runs — fine for set-membership
// callers, broken for any consumer that diffed the list (CLI help
// text, test goldens, generated docs). Sorting locks the order in.
func AllProfiles() []string {
	profilesMu.RLock()
	defer profilesMu.RUnlock()
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	return ids
}
