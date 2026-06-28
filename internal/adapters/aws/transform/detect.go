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

// enrichment describes a per-resource input that enriches a base asset rather
// than being a top-level list. Such inputs (e.g. get-bucket-encryption) carry no
// resource name, so the collector annotates them with a join key (e.g. Bucket);
// the filter emits {id, ...fragment} that merge-by-id folds onto the base asset.
// primaryKey identifies the input shape; joinKey is the annotation that supplies
// the merge id. A doc with primaryKey but no joinKey is skipped (no id to merge).
type enrichment struct {
	filter     string
	primaryKey string
	joinKey    string
}

// selfDescribingFilters are filters whose input carries its own identity (no
// top-level list key, no annotation) — e.g. an inline policy document. Listed so
// filter linting knows they are referenced.
var selfDescribingFilters = []string{"iam-inline-policy"}

// hasAnyPrincipal reports whether a raw doc names an IAM principal it belongs to.
func hasAnyPrincipal(raw map[string]any) bool {
	for _, k := range []string{"UserName", "GroupName", "RoleName"} {
		if _, ok := raw[k]; ok {
			return true
		}
	}
	return false
}

var enrichments = []enrichment{
	{"s3-public-access-block", "PublicAccessBlockConfiguration", "Bucket"},
	{"s3-encryption", "ServerSideEncryptionConfiguration", "Bucket"},
	{"s3-tags", "TagSet", "Bucket"},
	{"iam-role-attached-policies", "AttachedPolicies", "RoleArn"},
	{"iam-role-tags", "Tags", "RoleArn"},
}

// referencedFilters returns every filter name the runner can invoke (base list
// filters + enrichment filters). Used by filter linting to flag orphan or
// missing .jq files.
func referencedFilters() []string {
	out := make([]string, 0, len(topLevelKeyToFilter)+len(enrichments)+len(selfDescribingFilters))
	for _, f := range topLevelKeyToFilter {
		out = append(out, f)
	}
	for _, e := range enrichments {
		out = append(out, e.filter)
	}
	out = append(out, selfDescribingFilters...)
	sort.Strings(out)
	return out
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
	out := make([]Supported, 0, len(keys)+len(enrichments))
	for _, k := range keys {
		out = append(out, Supported{TopLevelKey: k, Filter: topLevelKeyToFilter[k]})
	}
	for _, e := range enrichments {
		out = append(out, Supported{
			TopLevelKey: e.primaryKey + " + " + e.joinKey,
			Filter:      e.filter + " (enrichment)",
		})
	}
	out = append(out, Supported{
		TopLevelKey: "PolicyDocument + (UserName|GroupName|RoleName)",
		Filter:      "iam-inline-policy (self-describing)",
	})
	return out
}

// detectFilter returns the filter name for a parsed raw document, and false when
// no filter recognizes it (the caller skips the file).
func detectFilter(raw map[string]any) (string, bool) {
	// Self-describing inline policy documents carry the principal + PolicyName +
	// PolicyDocument, so they map straight to a policy asset (not a merge
	// fragment). A PolicyDocument with no principal has no id and is skipped.
	if _, ok := raw["PolicyDocument"]; ok {
		if hasAnyPrincipal(raw) {
			return "iam-inline-policy", true
		}
		return "", false
	}

	// Enrichment inputs are matched next (more specific than base lists). An
	// enrichment whose primaryKey is present but whose joinKey (the annotation
	// supplying the merge id) is missing is skipped — no id to merge onto.
	for _, e := range enrichments {
		if _, ok := raw[e.primaryKey]; !ok {
			continue
		}
		if _, hasJoin := raw[e.joinKey]; hasJoin {
			return e.filter, true
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
