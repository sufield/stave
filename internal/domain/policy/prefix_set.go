package policy

import (
	"slices"
	"strings"
)

// PrefixSet is a normalized, sorted collection of path prefixes.
type PrefixSet struct {
	prefixes []string
}

// NewPrefixSet creates a PrefixSet from raw prefix strings.
// Each prefix is trimmed, given a trailing slash, and the result is sorted.
func NewPrefixSet(raw []string) PrefixSet {
	return PrefixSet{prefixes: normalizePrefixes(raw)}
}

// Empty reports whether the set contains no prefixes.
func (ps PrefixSet) Empty() bool { return len(ps.prefixes) == 0 }

// Paths returns the sorted, normalized prefix strings.
func (ps PrefixSet) Paths() []string { return ps.prefixes }

// PrefixConflict describes an overlap between an allowed and protected prefix.
type PrefixConflict struct {
	Allowed   string
	Protected string
}

// DetectOverlap finds the first path containment between allowed and protected
// prefix sets using a sorted merge cursor.
//
// Both sets are sorted. The algorithm merges them in order, tracking the most
// general (shortest) active prefix from each set. When an entry from one set
// falls under the active prefix of the other, that's a conflict.
func DetectOverlap(allowed, protected PrefixSet) *PrefixConflict {
	cursor := overlapCursorState{
		allowed:   allowed.prefixes,
		protected: protected.prefixes,
	}
	for cursor.hasNext() {
		var conflict *PrefixConflict
		if cursor.shouldPickAllowed() {
			conflict = cursor.advanceAllowed()
		} else {
			conflict = cursor.advanceProtected()
		}
		if conflict != nil {
			return conflict
		}
	}
	return nil
}

type overlapCursorState struct {
	allowed         []string
	protected       []string
	allowedIndex    int
	protectedIndex  int
	activeAllowed   string
	activeProtected string
}

func (s *overlapCursorState) hasNext() bool {
	return s.allowedIndex < len(s.allowed) || s.protectedIndex < len(s.protected)
}

func (s *overlapCursorState) shouldPickAllowed() bool {
	switch {
	case s.allowedIndex < len(s.allowed) && s.protectedIndex < len(s.protected):
		return s.allowed[s.allowedIndex] <= s.protected[s.protectedIndex]
	case s.allowedIndex < len(s.allowed):
		return true
	default:
		return false
	}
}

func (s *overlapCursorState) advanceAllowed() *PrefixConflict {
	current := s.allowed[s.allowedIndex]
	s.allowedIndex++
	if s.activeProtected != "" && strings.HasPrefix(current, s.activeProtected) {
		return &PrefixConflict{Allowed: current, Protected: s.activeProtected}
	}
	if s.activeAllowed == "" || !strings.HasPrefix(current, s.activeAllowed) {
		s.activeAllowed = current
	}
	return nil
}

func (s *overlapCursorState) advanceProtected() *PrefixConflict {
	current := s.protected[s.protectedIndex]
	s.protectedIndex++
	if s.activeAllowed != "" && strings.HasPrefix(current, s.activeAllowed) {
		return &PrefixConflict{Allowed: s.activeAllowed, Protected: current}
	}
	if s.activeProtected == "" || !strings.HasPrefix(current, s.activeProtected) {
		s.activeProtected = current
	}
	return nil
}

// normalizePrefixes trims whitespace, adds trailing slashes, deduplicates, and
// sorts the result.
func normalizePrefixes(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}

	result := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		result = append(result, p)
	}
	if len(result) == 0 {
		return nil
	}
	slices.Sort(result)
	return result
}
