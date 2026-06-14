package capabilities

// synonymMap translates the words users actually type into the
// catalog's canonical vocabulary. "Is my bucket open?" should
// surface the public-access capabilities; "orphaned policies"
// should surface the ghost-reference detection. Keys are the
// terms users type; values are the canonical Stave terms they
// should expand to in keyword sets and search hits.
//
// Bidirectional: the search command also looks up canonical terms
// to find user-input synonyms, so a search for "ghost" matches
// capabilities tagged "orphan" or "dangling".
var synonymMap = map[string][]string{
	"public":          {"open", "internet", "anonymous", "unauthenticated", "world", "allusers", "everyone"},
	"open":            {"public"},
	"internet":        {"public"},
	"anonymous":       {"public", "unauthenticated"},
	"unauthenticated": {"public", "anonymous"},
	"world":           {"public"},
	"everyone":        {"public"},

	"encryption": {"encrypt", "encrypted", "sse", "kms", "cipher", "tls"},
	"encrypt":    {"encryption"},
	"encrypted":  {"encryption"},
	"sse":        {"encryption"},
	"kms":        {"encryption", "key"},
	"tls":        {"encryption", "https"},
	"https":      {"tls", "transport"},

	"rotation": {"rotate", "expire", "expiry", "ttl", "lifecycle", "age"},
	"rotate":   {"rotation"},
	"expire":   {"rotation"},
	"expiry":   {"rotation"},
	"ttl":      {"rotation"},

	"ghost":    {"orphan", "orphaned", "dangling", "deleted", "missing"},
	"orphan":   {"ghost", "dangling"},
	"orphaned": {"ghost", "dangling"},
	"dangling": {"ghost", "orphan"},

	"admin":          {"administrator", "privileged", "overprivileged", "shadow"},
	"administrator":  {"admin"},
	"privileged":     {"admin"},
	"overprivileged": {"admin"},
	"shadow":         {"admin"},

	"mfa":       {"two-factor", "twofactor", "2fa"},
	"twofactor": {"mfa"},

	"drift":        {"change", "changed", "modification", "diff", "difference"},
	"change":       {"drift"},
	"changed":      {"drift"},
	"modification": {"drift"},
	"diff":         {"drift"},

	"duration": {"age", "how-long", "exposure", "window", "persistence"},
	"age":      {"duration"},
	"exposure": {"duration", "window"},
	"window":   {"duration", "exposure"},

	"proof":        {"prove", "z3", "smt", "formal", "verification"},
	"prove":        {"proof"},
	"verify":       {"proof"},
	"verification": {"proof"},

	"guardrail": {"safety", "filter", "moderation"},
	"safety":    {"guardrail"},

	"bucket":   {"s3", "storage"},
	"role":     {"iam", "identity"},
	"function": {"lambda", "compute"},
	"trail":    {"cloudtrail", "audit"},
	"queue":    {"sqs", "messaging"},
}

// SynonymsFor returns the canonical-form terms registered for the
// given token. Returns an empty slice when no synonyms exist.
func SynonymsFor(token string) []string {
	if v, ok := synonymMap[token]; ok {
		return v
	}
	return nil
}

// ExpandQuery returns the input tokens plus every registered synonym
// for them. Used by the search command to widen a user's query to
// the catalog's canonical vocabulary.
func ExpandQuery(tokens []string) []string {
	seen := map[string]struct{}{}
	for _, t := range tokens {
		if t == "" {
			continue
		}
		seen[t] = struct{}{}
		for _, syn := range SynonymsFor(t) {
			seen[syn] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
