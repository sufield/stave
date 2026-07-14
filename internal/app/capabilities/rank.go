package capabilities

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"
)

// Hit is one ranked capability plus its score breakdown. The JSON
// tags are part of the `stave search --format json` contract and the
// MCP search tool's wire shape — keep them stable.
type Hit struct {
	Capability Capability `json:"capability"`
	Score      float64    `json:"score"`
	MatchedOn  []string   `json:"matched_on,omitempty"`
}

// Rank scores every capability in the catalog against the free-form
// query, expanding synonyms so callers need not know Stave's
// vocabulary first. Results are sorted by descending score, ties
// broken by capability ID for determinism.
//
// Scoring (per matched token, summed):
//
//	title:        3
//	use_when:     2
//	keyword:      1
//	description:  0.5
//
// A verbatim multi-word phrase hit adds 5 (title) or 4 (use_when).
// A threshold of 2.0 filters single-token keyword/description noise.
func Rank(catalog []Capability, query string) []Hit {
	tokens := tokeniseQuery(query)
	expanded := ExpandQuery(tokens)
	phrase := toLowerTrim(query)

	out := make([]Hit, 0, 32)
	for i := range catalog {
		c := &catalog[i]
		score := 0.0
		var matched []string

		// Phrase bonus — verbatim multi-word match.
		if len(strings.Fields(phrase)) > 1 {
			if strutil.ContainsFold(c.Title, phrase) {
				score += 5
				matched = append(matched, "phrase:title")
			} else if strutil.ContainsFold(c.UseWhen, phrase) {
				score += 4
				matched = append(matched, "phrase:use_when")
			}
		}

		// Per-token scoring against title / use_when / keywords / description.
		titleHits := 0
		for _, tok := range expanded {
			if tok == "" {
				continue
			}
			if strutil.ContainsFold(c.Title, tok) {
				score += 3
				titleHits++
			}
			if strutil.ContainsFold(c.UseWhen, tok) {
				score += 2
			}
			for _, kw := range c.Keywords {
				if strings.EqualFold(kw, tok) || strutil.ContainsFold(kw, tok) {
					score += 1
					break
				}
			}
			if strutil.ContainsFold(c.Description, tok) {
				score += 0.5
			}
		}

		// Threshold of 2.0 filters single-token keyword (1.0) or
		// single-token description (0.5) noise. Requires at least a
		// title hit, a use_when hit, two keyword hits, or a phrase
		// match to surface.
		if score < 2.0 {
			continue
		}
		if titleHits > 0 {
			matched = append(matched, fmt.Sprintf("title×%d", titleHits))
		}
		out = append(out, Hit{Capability: *c, Score: score, MatchedOn: matched})
	}
	slices.SortFunc(out, func(a, b Hit) int {
		if a.Score != b.Score {
			return cmp.Compare(b.Score, a.Score) // descending
		}
		return cmp.Compare(a.Capability.ID, b.Capability.ID)
	})
	return out
}

// tokeniseQuery splits a free-form query into lowercase alphanumeric
// tokens of length >= 2. Kept here (rather than reusing the catalog's
// internal tokenise, which has a length-3 floor for indexing) so
// two-letter queries like "s3" still match.
func tokeniseQuery(s string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cur.WriteRune(r)
		default:
			if cur.Len() >= 2 {
				out = append(out, cur.String())
			}
			cur.Reset()
		}
	}
	if cur.Len() >= 2 {
		out = append(out, cur.String())
	}
	return out
}

func toLowerTrim(str string) string {
	trimmed := strings.TrimSpace(str)
	needsLower := false
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] >= 'A' && trimmed[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		return strings.ToLower(trimmed)
	}
	return trimmed
}
