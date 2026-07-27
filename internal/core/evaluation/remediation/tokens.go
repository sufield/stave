package remediation

// TokenDef maps a placeholder (e.g. "<bucket>") to an indication
// of which identifier to substitute.
type TokenDef struct {
	Placeholder string
	UseFullID   bool // false = short identifier, true = full asset ID
}

// TypeTokens maps asset type strings to their token definitions.
// Populated by the provider's Register function at startup.
var TypeTokens = map[string][]TokenDef{}
