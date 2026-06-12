package capabilities

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
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
	phrase := strings.ToLower(strings.TrimSpace(query))

	out := make([]Hit, 0, 32)
	for i := range catalog {
		c := &catalog[i]
		score := 0.0
		var matched []string

		titleLow := strings.ToLower(c.Title)
		useWhenLow := strings.ToLower(c.UseWhen)
		descLow := strings.ToLower(c.Description)

		// Phrase bonus — verbatim multi-word match.
		if len(strings.Fields(phrase)) > 1 {
			if strings.Contains(titleLow, phrase) {
				score += 5
				matched = append(matched, "phrase:title")
			} else if strings.Contains(useWhenLow, phrase) {
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
			if strings.Contains(titleLow, tok) {
				score += 3
				titleHits++
			}
			if strings.Contains(useWhenLow, tok) {
				score += 2
			}
			for _, kw := range c.Keywords {
				if kw == tok || strings.Contains(kw, tok) {
					score += 1
					break
				}
			}
			if strings.Contains(descLow, tok) {
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
	s = strings.ToLower(s)
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
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
