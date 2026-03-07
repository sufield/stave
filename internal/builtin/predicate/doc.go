// Package predicate provides built-in semantic predicate aliases used by Stave.
//
// These aliases expand short names (for example, "s3.is_public_readable")
// into concrete predicate rule trees consumed by control evaluation.
// [Resolve] returns a deep copy so callers cannot mutate the registry.
package predicate
