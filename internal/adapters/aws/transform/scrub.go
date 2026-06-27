package transform

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// scrub.go redacts sensitive VALUES from a produced asset while preserving the
// structure and the configuration Stave controls actually read. It is an
// allowlist of what to hash — everything else is left untouched — so it can
// NEVER damage policy documents, security-group rules, ARNs, names, actions, or
// conditions. Redacted strings become "sha256:<hex>" so identical secrets still
// compare equal across snapshots (drift stays detectable) without exposing the
// value.

// secretTagKey matches tag/metadata keys whose values are secrets. Deliberately
// narrow: it must not match benign keys like "Name" or "Environment".
var secretTagKey = regexp.MustCompile(`(?i)(secret|password|passwd|token|credential|api[_-]?key|private[_-]?key)`)

func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// scrubAsset walks an asset (decoded from a filter's JSON output) and hashes
// sensitive values in place.
func scrubAsset(v any) {
	scrubNode(v, "")
}

// scrubNode recurses through the decoded JSON. parentKey is the key under which
// the current node sits, used to decide context-sensitive rules (e.g. hashing
// every value inside a Lambda env `Variables` object).
func scrubNode(v any, parentKey string) {
	switch node := v.(type) {
	case map[string]any:
		inEnvVars := strings.EqualFold(parentKey, "variables") || strings.EqualFold(parentKey, "environment_variables")
		for k, child := range node {
			if s, ok := child.(string); ok {
				switch {
				case strings.EqualFold(k, "userdata"):
					node[k] = hashValue(s)
				case inEnvVars:
					node[k] = hashValue(s)
				case secretTagKey.MatchString(k):
					node[k] = hashValue(s)
				}
				continue
			}
			scrubNode(child, k)
		}
	case []any:
		for _, child := range node {
			scrubNode(child, parentKey)
		}
	}
}
