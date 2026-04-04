package controldef

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// PrefixSet represents a normalized, sorted, and non-redundant collection of path prefixes.
// The zero value is a valid empty set.
type PrefixSet struct {
	prefixes []kernel.ObjectPrefix
}

// NewPrefixSet constructs a PrefixSet from raw strings.
// It handles normalization, sorting, and removal of redundant sub-paths.
func NewPrefixSet(prefixes ...string) PrefixSet {
	return PrefixSet{prefixes: normalizePrefixes(prefixes)}
}

// Empty reports whether the set contains no path prefixes.
func (ps PrefixSet) Empty() bool {
	return len(ps.prefixes) == 0
}

// Prefixes returns a copy of the sorted, normalized object prefixes.
func (ps PrefixSet) Prefixes() []kernel.ObjectPrefix {
	return slices.Clone(ps.prefixes)
}

// PrefixConflict identifies a path containment collision between an allowed and protected prefix.
type PrefixConflict struct {
	Allowed   kernel.ObjectPrefix
	Protected kernel.ObjectPrefix
}

// Overlap identifies the first instance where a prefix from this set
// contains or is contained by a prefix in the other set.
// Both sets must be sorted; runs in O(N+M).
func (ps PrefixSet) Overlap(other PrefixSet) *PrefixConflict {
	aIdx, oIdx := 0, 0
	aLen, oLen := len(ps.prefixes), len(other.prefixes)

	for aIdx < aLen && oIdx < oLen {
		a := string(ps.prefixes[aIdx])
		o := string(other.prefixes[oIdx])

		switch {
		case strings.HasPrefix(a, o):
			return &PrefixConflict{Allowed: ps.prefixes[aIdx], Protected: other.prefixes[oIdx]}
		case strings.HasPrefix(o, a):
			return &PrefixConflict{Allowed: ps.prefixes[aIdx], Protected: other.prefixes[oIdx]}
		}

		if a < o {
			aIdx++
		} else {
			oIdx++
		}
	}

	return nil
}

// normalizePrefixes cleanses input strings and removes logical redundancies.
func normalizePrefixes(raw []string) []kernel.ObjectPrefix {
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
		p = kernel.EnsureTrailingSlash(p)
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

	// 4. Convert to ObjectPrefix
	result := make([]kernel.ObjectPrefix, len(clean))
	for i, p := range clean {
		result[i] = kernel.ObjectPrefix(p)
	}
	return result
}
