package transform

import "sort"

// detect.go maps a raw AWS CLI document to the filter that converts it, keyed by
// the top-level JSON key AWS uses for the resource (e.g. `aws iam list-roles`
// returns `{"Roles":[...]}`). A file whose top-level key matches nothing is
// skipped rather than failing the run — the user may collect more than Stave
// converts today.

// topLevelKeyToFilter maps the distinctive top-level key of a raw AWS CLI list
// response to its base filter. Order does not matter; the first present key wins.
var topLevelKeyToFilter = map[string]string{
	"PasswordPolicy": "iam-password-policy",
	"Roles":          "iam-roles",
	"Buckets":        "s3-buckets",
}

// Supported describes one recognized raw input shape, for `stave transform
// --coverage`.
type Supported struct {
	TopLevelKey string `json:"top_level_key"`
	Filter      string `json:"filter"`
}

// SupportedInputs lists the raw AWS CLI shapes transform recognizes, sorted by
// top-level key. Enrichment inputs that need a join key are noted in the filter
// name.
func SupportedInputs() []Supported {
	keys := make([]string, 0, len(topLevelKeyToFilter))
	for k := range topLevelKeyToFilter {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Supported, 0, len(keys)+1)
	for _, k := range keys {
		out = append(out, Supported{TopLevelKey: k, Filter: topLevelKeyToFilter[k]})
	}
	out = append(out, Supported{TopLevelKey: "PublicAccessBlockConfiguration + Bucket", Filter: "s3-public-access-block (enrichment)"})
	return out
}

// detectFilter returns the filter name for a parsed raw document, and false when
// no filter recognizes it (the caller skips the file).
func detectFilter(raw map[string]any) (string, bool) {
	// Enrichment filters are matched first (more specific). A per-bucket
	// public-access-block must carry the bucket name ("Bucket") so it can be
	// merged onto the base asset by id; an un-annotated PAB file has no join key
	// and is skipped rather than producing an orphan or failing the run.
	if _, ok := raw["PublicAccessBlockConfiguration"]; ok {
		if _, hasKey := raw["Bucket"]; hasKey {
			return "s3-public-access-block", true
		}
		return "", false
	}

	for key, filter := range topLevelKeyToFilter {
		if _, ok := raw[key]; ok {
			return filter, true
		}
	}
	return "", false
}
