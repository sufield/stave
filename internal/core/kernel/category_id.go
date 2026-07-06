package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// CategoryID identifies a security concept category from the taxonomy
// vocabulary (e.g. "trust-boundary", "formal-semantics"). The kernel
// owns the type so domain types in core/controldef can reference it
// without importing the (consumer-facing) taxonomy package.
//
// The vocabulary is registered by the taxonomy package's init() via
// SetCategoryIDVocabulary so Validate / IsValid can reject unknown
// IDs. Until registered (e.g. in a minimal test harness that doesn't
// import taxonomy) Validate degrades to non-empty check only.
type CategoryID string

type categoryVocabulary struct {
	mu  sync.RWMutex
	ids map[CategoryID]struct{}
}

func (v *categoryVocabulary) replace(ids []string) {
	set := make(map[CategoryID]struct{}, len(ids))
	for _, id := range ids {
		set[CategoryID(id)] = struct{}{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ids = set
}

func (v *categoryVocabulary) known(c CategoryID) (registered, ok bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.ids == nil {
		return false, false
	}
	_, ok = v.ids[c]
	return true, ok
}

var categoryVocab = &categoryVocabulary{}

// SetCategoryIDVocabulary registers the canonical set of taxonomy
// category IDs against which CategoryID.Validate / IsValid will check.
// The taxonomy package calls this from its init(). Call once at
// startup; later calls replace the vocabulary.
func SetCategoryIDVocabulary(ids []string) {
	categoryVocab.replace(ids)
}

func (c CategoryID) String() string { return string(c) }

// IsEmpty reports whether the ID is unset.
func (c CategoryID) IsEmpty() bool { return c == "" }

// IsValid reports whether the ID is a member of the registered
// taxonomy vocabulary. When no vocabulary is registered (test
// harnesses that don't import taxonomy), returns true for any
// non-empty value.
func (c CategoryID) IsValid() bool {
	if c.IsEmpty() {
		return false
	}
	registered, ok := categoryVocab.known(c)
	if !registered {
		return true
	}
	return ok
}

// Validate enforces non-empty plus vocabulary membership when
// the vocabulary is registered.
func (c CategoryID) Validate() error {
	if c.IsEmpty() {
		return errors.New("taxonomy category ID must not be empty")
	}
	registered, ok := categoryVocab.known(c)
	if !registered {
		return nil
	}
	if !ok {
		return fmt.Errorf("unknown taxonomy category %q: not in vocabulary", string(c))
	}
	return nil
}

// NewCategoryID returns a validated CategoryID.
func NewCategoryID(raw string) (CategoryID, error) {
	id := CategoryID(raw)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// UnmarshalText delegates to NewCategoryID so YAML / text inputs
// share one validation gate.
func (c *CategoryID) UnmarshalText(text []byte) error {
	parsed, err := NewCategoryID(string(text))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (c CategoryID) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// MarshalJSON serializes as a JSON string.
func (c CategoryID) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (c *CategoryID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return c.UnmarshalText([]byte(s))
}
