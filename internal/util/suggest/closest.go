// Package suggest provides fuzzy string matching utilities for CLI hints.
package suggest

import "github.com/sufield/stave/internal/util/strutil"

// Distance thresholds bucket inputs by length: short inputs (typos in
// flags / short subcommands) tolerate at most one edit, while longer
// inputs (full command paths, identifiers) tolerate progressively
// more edits. Bucketing prevents a 3-character typo from suggesting a
// 12-character command that happens to share a few letters.
const (
	shortInputMaxLen       = 4
	mediumInputMaxLen      = 8
	longInputMaxLen        = 14
	shortInputMaxDistance  = 1
	mediumInputMaxDistance = 3
	longInputMaxDistance   = 5
	xLongInputMaxDistance  = 6
)

// Closest returns the candidate most similar to input based on Levenshtein distance.
// It returns an empty string if no candidate meets the distance threshold.
func Closest(input string, candidates []string) string {
	query := normalize(input)
	if query == "" || len(candidates) == 0 {
		return ""
	}

	maxDist := threshold(len(query))
	best := ""
	bestNorm := ""
	bestDist := maxDist + 1

	for _, candidate := range candidates {
		norm := normalize(candidate)
		if norm == "" {
			continue
		}

		d := Distance(query, norm)
		if d > maxDist {
			continue
		}
		// Tertiary tiebreak on the original (non-normalized) string
		// guarantees deterministic output when two candidates
		// normalise to the same value (e.g. "stave-init" and
		// "Stave-Init" both → "stave-init"). Without it the result
		// depended on iteration order — fine for `range slice`, but
		// not for `range map` which produces a different
		// suggestion across runs.
		if best == "" ||
			d < bestDist ||
			(d == bestDist && norm < bestNorm) ||
			(d == bestDist && norm == bestNorm && candidate < best) {
			best = candidate
			bestNorm = norm
			bestDist = d
		}
	}

	return best
}

func normalize(s string) string {
	return strutil.ToLowerTrim(s)
}

func threshold(inputLen int) int {
	switch {
	case inputLen <= shortInputMaxLen:
		return shortInputMaxDistance
	case inputLen <= mediumInputMaxLen:
		return mediumInputMaxDistance
	case inputLen <= longInputMaxLen:
		return longInputMaxDistance
	default:
		return xLongInputMaxDistance
	}
}

// Distance returns the Levenshtein edit distance between two strings,
// measured in runes rather than bytes. Indexing strings as []byte
// counted multi-byte UTF-8 characters as multiple edits — a single
// emoji or accented character could compare as 2–4 edits against an
// otherwise identical string. Convert to rune slices before the DP
// pass so user-visible characters map 1:1 to edit operations.
func Distance(a, b string) int {
	if a == b {
		return 0
	}
	ar := []rune(a)
	br := []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}

	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}
			curr[j] = min(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}

	return prev[len(br)]
}
