package sensitive

// substringKeywords are partial-match needles for detecting sensitive keys.
// Order is irrelevant; these are checked via strings.Contains.
var substringKeywords = []string{
	"secret", "token", "password", "credential", "auth", "bearer",
	"private", "api_key", "access_key",
}

// exactKeys provides O(1) lookup for exact sensitive key names.
// Includes both canonical (underscore) and collapsed (no separator) forms.
var exactKeys = map[string]struct{}{
	"token": {}, "secret": {}, "password": {}, "key": {},
	"credential": {}, "auth": {}, "bearer": {},
	"api_key": {}, "apikey": {},
	"access_token": {}, "accesstoken": {},
	"refresh_token": {}, "refreshtoken": {},
	"private_key": {}, "privatekey": {},
	"signing_key": {}, "signingkey": {},
	"access_key": {},
}

// SubstringKeywords returns a copy of the substring-match keywords.
func SubstringKeywords() []string {
	return append([]string(nil), substringKeywords...)
}

// IsExactKey reports whether key is in the exact-match set.
func IsExactKey(key string) bool {
	_, ok := exactKeys[key]
	return ok
}
