// Package ports defines dependency-injection interfaces for the domain layer.
//
// [Clock] abstracts time for deterministic evaluation and testing.
// [Verifier] abstracts cryptographic signature validation.
// [ContentHasher] computes reproducible digests over file system paths.
package ports
