package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ArchetypeID identifies a structural defect classification (the
// archetype catalog in internal/archetype/catalog.go). The kernel
// owns the type so domain types in core/controldef and
// core/evaluation can reference it without importing the
// (consumer-facing) archetype package.
//
// The catalog vocabulary is registered by the archetype package's
// init() via SetArchetypeIDVocabulary so Validate / IsValid can
// reject unknown IDs. Until the vocabulary is registered (e.g. in a
// minimal test harness that doesn't import archetype) Validate
// degrades to non-empty + slug-case shape only.
type ArchetypeID string

// archetypeVocabulary is the concurrency-safe set of valid archetype IDs.
// Bundling the map with the RWMutex that guards it keeps the lock and the data
// it protects in one type; a nil map means no vocabulary has been registered
// yet, at which point the kernel cannot reject on vocabulary grounds.
type archetypeVocabulary struct {
	mu  sync.RWMutex
	ids map[ArchetypeID]struct{}
}

// replace installs ids as the canonical vocabulary, replacing any prior set.
func (v *archetypeVocabulary) replace(ids []string) {
	set := make(map[ArchetypeID]struct{}, len(ids))
	for _, id := range ids {
		set[ArchetypeID(id)] = struct{}{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ids = set
}

// known reports membership. registered is false when no vocabulary has been
// set, in which case callers treat any non-empty ID as acceptable.
func (v *archetypeVocabulary) known(a ArchetypeID) (registered, ok bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.ids == nil {
		return false, false
	}
	_, ok = v.ids[a]
	return true, ok
}

// archetypeVocab is the process-wide archetype-ID vocabulary — one cohesive
// registry instance rather than a loose mutex+map pair.
var archetypeVocab = &archetypeVocabulary{}

// SetArchetypeIDVocabulary registers the canonical set of archetype
// IDs against which ArchetypeID.Validate / IsValid will check. The
// archetype package calls this from its init() with the catalog
// IDs. Call once at startup; later calls replace the vocabulary.
func SetArchetypeIDVocabulary(ids []string) {
	archetypeVocab.replace(ids)
}

// String returns the raw ID.
func (a ArchetypeID) String() string { return string(a) }

// IsEmpty reports whether the ID is unset.
func (a ArchetypeID) IsEmpty() bool { return a == "" }

// IsValid reports whether the ID is a member of the registered
// archetype vocabulary. When no vocabulary is registered (test
// harnesses that don't import archetype), IsValid returns true for
// any non-empty value — at that point the catalog cannot be
// consulted, so the kernel cannot reject on vocabulary grounds.
func (a ArchetypeID) IsValid() bool {
	if a.IsEmpty() {
		return false
	}
	registered, ok := archetypeVocab.known(a)
	if !registered {
		return true
	}
	return ok
}

// Validate enforces non-empty plus catalog membership when the
// vocabulary is registered.
func (a ArchetypeID) Validate() error {
	if a.IsEmpty() {
		return errors.New("archetype ID must not be empty")
	}
	registered, ok := archetypeVocab.known(a)
	if !registered {
		return nil
	}
	if !ok {
		return fmt.Errorf("invalid archetype ID %q: not in catalog vocabulary", string(a))
	}
	return nil
}

// NewArchetypeID returns a validated ArchetypeID.
func NewArchetypeID(raw string) (ArchetypeID, error) {
	id := ArchetypeID(raw)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// UnmarshalText delegates to NewArchetypeID so YAML / text inputs
// share one validation gate.
func (a *ArchetypeID) UnmarshalText(text []byte) error {
	parsed, err := NewArchetypeID(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (a ArchetypeID) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// MarshalJSON serializes as a JSON string.
func (a ArchetypeID) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (a *ArchetypeID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}
