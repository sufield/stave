// Package sanitize provides a deterministic sanitization engine for
// infrastructure identifiers in Stave CLI output.
//
// [Sanitizer] replaces asset IDs, file paths, and arbitrary values with
// deterministic pseudonyms or basenames. [OutputSanitizationPolicy]
// bridges CLI flags to Sanitizer configuration.
//
// Snapshot-level scrubbing (removing sensitive property keys from observation
// data before persistence) lives in the [scrub] sub-package.
package sanitize
