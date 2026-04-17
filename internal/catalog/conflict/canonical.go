package conflict

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Canonical-form helpers for inputs that get hashed into the
// ConflictReport. The canonical form is part of the report contract:
// any change to these functions invalidates every cached
// shared_compliance_hash and shared_remediation_hash in downstream
// consumers, so the helpers exist as a single, named, stable surface.
//
// Pinned inputs and outputs live in `canonical_test.go` as golden
// pairs. If you change canonicalization, you are also changing the
// hash — update the golden test deliberately and document the bump in
// the ontology CHANGELOG.

// CanonicalCompliance returns the canonical byte sequence used as
// input to shared_compliance_hash for a set of compliance citation
// tokens (e.g., "PCI-DSS:1.2", "SOC2:CC6.1").
//
// Form: items are deduplicated, sorted ascending using Go's default
// byte-wise string comparison, joined with U+007C (pipe). No leading
// or trailing whitespace, no normalization beyond dedup-and-sort.
// Empty input → empty string.
//
// Example:
//
//	CanonicalCompliance([]string{"SOC2:CC6.1", "PCI-DSS:1.2", "SOC2:CC6.1"})
//	  → "PCI-DSS:1.2|SOC2:CC6.1"
//
// Tokens are compared byte-by-byte; case is preserved. Callers that
// want case-insensitive equivalence must lowercase before calling.
func CanonicalCompliance(items []string) string {
	if len(items) == 0 {
		return ""
	}
	s := slices.Clone(items)
	slices.Sort(s)
	s = slices.Compact(s)
	return strings.Join(s, "|")
}

// CanonicalRemediation returns the canonical byte sequence used as
// input to shared_remediation_hash for a control's remediation block.
//
// Form: action and example are each whitespace-collapsed (every run
// of Unicode whitespace becomes a single ASCII space, leading and
// trailing whitespace stripped), then joined with U+007C (pipe). The
// separator is always present even when one side is empty —
// "action|" and "|example" are distinct from "action|example".
//
// Example:
//
//	CanonicalRemediation("Block public access", "  aws s3api put-public-access-block ...")
//	  → "Block public access|aws s3api put-public-access-block ..."
//
// Whitespace collapse is intentional: remediation guidance frequently
// wraps differently across catalog edits without semantic change, and
// hashing the raw bytes would churn hashes unnecessarily.
func CanonicalRemediation(action, example string) string {
	return collapseWhitespace(action) + "|" + collapseWhitespace(example)
}

// HashSHA256 returns "sha256:" followed by the lowercase hex SHA-256
// digest of s. Used by shared_compliance_hash and shared_remediation_hash
// in the ConflictReport.
func HashSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// collapseWhitespace replaces every run of Unicode whitespace with a
// single ASCII space and trims leading/trailing whitespace.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
