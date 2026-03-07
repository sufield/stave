// Package dbc provides design-by-contract assertion helpers.
//
// [ExpensiveCheck] runs O(n) correctness assertions in debug builds and
// compiles to a no-op in release builds, allowing thorough internal
// validation without production overhead.
package dbc
