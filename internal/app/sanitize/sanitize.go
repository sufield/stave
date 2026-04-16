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

// Sanitize applies sanitization rules to snapshots in place.
func Sanitize(snapshots []asset.Snapshot, cfg Config) {
	for i := range snapshots {
		snap := &snapshots[i]
		for j := range snap.Assets {
			a := &snap.Assets[j]
			for _, rule := range cfg.Rules {
				applyRule(a, rule)
			}
			// Always hash account IDs in string property values.
			sanitizeAccountIDs(a.Properties)
		}
	}
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
func sanitizeAccountIDs(props map[string]any) {
	for key, val := range props {
		switch v := val.(type) {
		case string:
			props[key] = accountIDRegexp.ReplaceAllStringFunc(v, func(match string) string {
				return hashToken(match)
			})
		case map[string]any:
			sanitizeAccountIDs(v)
		}
	}
}
