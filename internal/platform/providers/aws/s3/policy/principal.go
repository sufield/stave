package policy

import "regexp"

// Internal constants for AWS principal type keys. Lowercased so the
// case-insensitive map walk in NormalizedPrincipal.populate matches
// regardless of how the policy author capitalised "AWS" / "Service" /
// "Federated" / "CanonicalUser".
const (
	keyAWS           = "aws"
	keyService       = "service"
	keyFederated     = "federated"
	keyCanonicalUser = "canonicaluser"
)

// reAccountID matches exactly 12 digits (AWS Account ID format).
var reAccountID = regexp.MustCompile(`^\d{12}$`)

// isAccountIDOnly reports whether the principal is a bare 12-digit
// account ID. Used by NormalizedPrincipal.classifyAWSARNs to
// distinguish a whole-account principal from a specific role/user
// ARN; account-ID-only stays at ScopeAccount even though it is
// technically an "any-principal-in-the-account" reference.
//
// The legacy NewPrincipal / Principal / analyzeMap / classifyAWSPrincipal
// chain that used to live in this file has been retired — every
// caller now goes through NormalizedPrincipal's typed methods (Scope,
// ConcreteAWSARNs, IsEmpty). The keyAWS / keyService / keyFederated /
// keyCanonicalUser constants and isAccountIDOnly are the only
// helpers still consumed from outside this file (by normalized.go).
func isAccountIDOnly(principal string) bool {
	return reAccountID.MatchString(principal)
}
