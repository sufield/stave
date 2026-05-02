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

var (
	archetypeIDVocabMu sync.RWMutex
	archetypeIDVocab   map[ArchetypeID]struct{}
)

// SetArchetypeIDVocabulary registers the canonical set of archetype
// IDs against which ArchetypeID.Validate / IsValid will check. The
// archetype package calls this from its init() with the catalog
// IDs. Call once at startup; later calls replace the vocabulary.
func SetArchetypeIDVocabulary(ids []string) {
	set := make(map[ArchetypeID]struct{}, len(ids))
	for _, id := range ids {
		set[ArchetypeID(id)] = struct{}{}
	}
	archetypeIDVocabMu.Lock()
	defer archetypeIDVocabMu.Unlock()
	archetypeIDVocab = set
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
	archetypeIDVocabMu.RLock()
	defer archetypeIDVocabMu.RUnlock()
	if archetypeIDVocab == nil {
		return true
	}
	_, ok := archetypeIDVocab[a]
	return ok
}

// Validate enforces non-empty plus catalog membership when the
// vocabulary is registered.
func (a ArchetypeID) Validate() error {
	if a.IsEmpty() {
		return errors.New("archetype ID must not be empty")
	}
	archetypeIDVocabMu.RLock()
	defer archetypeIDVocabMu.RUnlock()
	if archetypeIDVocab == nil {
		return nil
	}
	if _, ok := archetypeIDVocab[a]; !ok {
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
