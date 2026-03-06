//go:build debug

package dbc

// ExpensiveCheck runs fn only in debug builds.
// Use for O(n) correctness checks that are too costly for production.
func ExpensiveCheck(fn func()) { fn() }
