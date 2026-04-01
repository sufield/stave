// Package suggest provides fuzzy string matching utilities for CLI hints.
package suggest

import "strings"

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
		if best == "" || d < bestDist || (d == bestDist && norm < bestNorm) {
			best = candidate
			bestNorm = norm
			bestDist = d
		}
	}

	return best
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func threshold(inputLen int) int {
	switch {
	case inputLen <= 4:
		return 1
	case inputLen <= 8:
		return 3
	case inputLen <= 14:
		return 5
	default:
		return 6
	}
}

// Distance returns the Levenshtein edit distance between two strings.
func Distance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
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

	return prev[len(b)]
}
