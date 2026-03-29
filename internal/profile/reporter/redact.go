package reporter

// RedactAccountID returns a partially redacted account ID showing only
// the last 4 digits: "123456789012" → "********9012".
func RedactAccountID(accountID string) string {
	if len(accountID) <= 4 {
		return accountID
	}
	redacted := make([]byte, len(accountID))
	for i := range redacted {
		redacted[i] = '*'
	}
	copy(redacted[len(redacted)-4:], accountID[len(accountID)-4:])
	return string(redacted)
}
