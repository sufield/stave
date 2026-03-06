//go:build !debug

package dbc

// ExpensiveCheck is a no-op in release builds.
func ExpensiveCheck(fn func()) {}
