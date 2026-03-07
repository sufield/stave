// Package predicate implements operator semantics for unsafe-predicate evaluation.
//
// It provides canonical operator definitions (eq, ne, gt, lt, missing, present,
// in, list_empty, not_subset_of_field, neq_field, not_in_field, contains,
// any_match) along with type-aware comparison logic and collection operations.
// The domain evaluation engine delegates field-level matching to this package.
package predicate
