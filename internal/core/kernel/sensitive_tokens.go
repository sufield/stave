package kernel

// SensitiveTokens are individual words that mark a compound field or flag
// name as sensitive when they appear as a discrete segment (split on _-.:).
// Defined in the core layer so both the evidence builder and the sanitize
// adapter can reference them without a cross-layer import.
var SensitiveTokens = map[string]struct{}{
	"token":      {},
	"secret":     {},
	"password":   {},
	"credential": {},
	"auth":       {},
	"bearer":     {},
	"key":        {},
}
