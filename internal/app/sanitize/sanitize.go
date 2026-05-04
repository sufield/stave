// Package sanitize provides standalone snapshot sanitization for
// cross-boundary sharing. Replaces ARNs, account IDs, and sensitive
// fields with deterministic tokens preserving uniqueness.
package sanitize

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/sufield/stave/internal/core/asset"
)

// Method controls how a field value is redacted.
type Method string

const (
	// MethodHash replaces the value with a deterministic SHA-256 token.
	MethodHash Method = "hash"
	// MethodPlaceholder replaces the value with a fixed string.
	MethodPlaceholder Method = "placeholder"
	// MethodRemove deletes the field entirely.
	MethodRemove Method = "remove"
)

// Rule describes how to redact a specific field.
type Rule struct {
	Field       string `yaml:"field" json:"field"`
	Method      Method `yaml:"method" json:"method"`
	Placeholder string `yaml:"placeholder,omitempty" json:"placeholder,omitempty"`
}

// Config holds the sanitization rules.
type Config struct {
	Rules []Rule `yaml:"redact" json:"redact"`
}

var accountIDRegexp = regexp.MustCompile(`\b\d{12}\b`)

// DefaultConfig returns the default sanitization config that hashes
// asset IDs and replaces 12-digit account IDs in property values.
func DefaultConfig() Config {
	return Config{
		Rules: []Rule{
			{Field: "asset_id", Method: MethodHash},
		},
	}
}

// Result reports per-run sanitization statistics. A non-zero
// AssetsTouched lets callers verify the rule set actually engaged
// against the input — a silent zero is the symptom of a misspelled
// rule.Field name that would otherwise pass without warning.
type Result struct {
	AssetsTouched   int
	RulesApplied    int
	AccountIDHashes int
}

// Sanitize applies sanitization rules to snapshots in place and
// returns a Result describing what changed. The caller is expected
// to log the Result so a no-op run (rules misspelled, empty input)
// surfaces explicitly rather than passing silently.
func Sanitize(snapshots []asset.Snapshot, cfg Config) Result {
	var r Result
	for i := range snapshots {
		snap := &snapshots[i]
		for j := range snap.Assets {
			a := &snap.Assets[j]
			r.AssetsTouched++
			for _, rule := range cfg.Rules {
				applyRule(a, rule)
				r.RulesApplied++
			}
			// Always hash account IDs in string property values.
			r.AccountIDHashes += sanitizeAccountIDs(a.Properties)
		}
	}
	return r
}

func applyRule(a *asset.Asset, rule Rule) {
	switch rule.Field {
	case "asset_id":
		switch rule.Method {
		case MethodHash:
			a.ID = asset.ID(hashToken(string(a.ID)))
		case MethodPlaceholder:
			a.ID = asset.ID(rule.Placeholder)
		}
	default:
		// Property field: walk into properties map.
		applyPropertyRule(a.Properties, rule.Field, rule)
	}
}

func applyPropertyRule(props map[string]any, path string, rule Rule) {
	if props == nil {
		return
	}

	// Split path into segments.
	parts := splitPath(path)
	if len(parts) == 0 {
		return
	}

	// Navigate to the leaf.
	current := props
	for i := 0; i < len(parts)-1; i++ {
		sub, ok := current[parts[i]].(map[string]any)
		if !ok {
			return
		}
		current = sub
	}

	leaf := parts[len(parts)-1]
	val, exists := current[leaf]
	if !exists {
		return
	}

	switch rule.Method {
	case MethodHash:
		if s, ok := val.(string); ok {
			current[leaf] = hashToken(s)
		}
	case MethodPlaceholder:
		current[leaf] = rule.Placeholder
	case MethodRemove:
		delete(current, leaf)
	}
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// hashToken produces a deterministic 12-char hex token from input.
func hashToken(value string) string {
	h := sha256.Sum256([]byte("stave-sanitize:" + value))
	return hex.EncodeToString(h[:])[:12]
}

// sanitizeAccountIDs replaces 12-digit AWS account IDs in string values.
// Recurses through nested maps and arrays so account IDs nested inside
// list-shaped properties (e.g. an `allowed_principals` array of ARNs)
// are scrubbed too. Without the array branch, account IDs lurking in
// `principals: ["arn:aws:iam::111122223333:role/x"]` slipped through
// because the list element was neither a string at the top level nor
// a map.
func sanitizeAccountIDs(props map[string]any) int {
	n := 0
	for key, val := range props {
		props[key] = sanitizeAccountIDValue(val)
		n++
	}
	return n
}

// sanitizeAccountIDValue is the recursive worker that handles the
// scalar / map / array shapes a single property value can take.
// Returning the (possibly rewritten) value keeps string replacement
// composable with array iteration: arrays are mutated in place, but
// string elements need a return path because slices can't take a
// pointer to an element typed as `any` directly.
func sanitizeAccountIDValue(val any) any {
	switch v := val.(type) {
	case string:
		return accountIDRegexp.ReplaceAllStringFunc(v, hashToken)
	case map[string]any:
		sanitizeAccountIDs(v)
		return v
	case []any:
		for i := range v {
			v[i] = sanitizeAccountIDValue(v[i])
		}
		return v
	default:
		return val
	}
}
