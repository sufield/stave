package sensitive

// SubstringKeywords are partial-match needles for detecting sensitive keys.
// Order is irrelevant; these are checked via strings.Contains.
var SubstringKeywords = []string{
	"secret", "token", "password", "credential", "auth", "bearer",
	"private", "api_key", "access_key",
}

// ExactKeys provides O(1) lookup for exact sensitive key names.
// Includes both canonical (underscore) and collapsed (no separator) forms.
var ExactKeys = map[string]struct{}{
	"token": {}, "secret": {}, "password": {}, "key": {},
	"credential": {}, "auth": {}, "bearer": {},
	"api_key": {}, "apikey": {},
	"access_token": {}, "accesstoken": {},
	"refresh_token": {}, "refreshtoken": {},
	"private_key": {}, "privatekey": {},
	"signing_key": {}, "signingkey": {},
	"access_key": {},
}
