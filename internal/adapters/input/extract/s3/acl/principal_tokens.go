package acl

import "strings"

const (
	principalTokenAllUsers           = "allusers"
	principalTokenAuthenticatedUsers = "authenticatedusers"
)

func isAllUsersPrincipalToken(value string) bool {
	return strings.Contains(strings.ToLower(value), principalTokenAllUsers)
}

func isAuthenticatedUsersPrincipalToken(value string) bool {
	return strings.Contains(strings.ToLower(value), principalTokenAuthenticatedUsers)
}
