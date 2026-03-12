package policy

import (
	"slices"
	"strings"
)

// PrefixSet represents a normalized, sorted, and non-redundant collection of path prefixes.
type PrefixSet struct {
	prefixes []string
}

// NewPrefixSet constructs a PrefixSet.
// It trims whitespace, ensures trailing slashes, deduplicates, and removes redundant sub-paths.
func NewPrefixSet(raw []string) PrefixSet {
	return PrefixSet{prefixes: normalizePrefixes(raw)}
}

// Empty reports whether the set contains no path prefixes.
func (ps PrefixSet) Empty() bool {
	return len(ps.prefixes) == 0
}

// Paths returns the sorted, normalized prefix strings.
func (ps PrefixSet) Paths() []string {
	return ps.prefixes
}

// PrefixConflict identifies a path containment collision between an allowed and protected prefix.
type PrefixConflict struct {
	Allowed   string
	Protected string
}

// DetectOverlap identifies the first instance where a prefix from the allowed set
// contains or is contained by a prefix in the protected set.
func DetectOverlap(allowed, protected PrefixSet) *PrefixConflict {
	aIdx, pIdx := 0, 0
	aLen, pLen := len(allowed.prefixes), len(protected.prefixes)

	for aIdx < aLen && pIdx < pLen {
		a := allowed.prefixes[aIdx]
		p := protected.prefixes[pIdx]

		switch {
		case strings.HasPrefix(a, p):
			// Protected prefix is higher/equal (e.g., p="a/", a="a/b/")
			return &PrefixConflict{Allowed: a, Protected: p}
		case strings.HasPrefix(p, a):
			// Allowed prefix is higher (e.g., a="a/", p="a/b/")
			return &PrefixConflict{Allowed: a, Protected: p}
		}

		// Move the pointer that is lexicographically smaller
		if a < p {
			aIdx++
		} else {
			pIdx++
		}
	}

	return nil
}

// normalizePrefixes cleanses input strings and removes logical redundancies.
func normalizePrefixes(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	// 1. Basic normalization (Trim, trailing slash, skip empty)
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		out = append(out, p)
	}

	if len(out) == 0 {
		return nil
	}

	// 2. Sort and Deduplicate
	slices.Sort(out)
	out = slices.Compact(out)

	// 3. Remove redundant sub-paths (O(N))
	// If we have ["a/", "a/b/"], "a/b/" is redundant because "a/" is more general.
	clean := out[:0]
	for _, p := range out {
		if len(clean) > 0 && strings.HasPrefix(p, clean[len(clean)-1]) {
			continue
		}
		clean = append(clean, p)
	}

	return clean
}
