// Package sanitize provides deterministic identifier masking for evaluation
// output.
//
// [Engine] applies scrub policies to observations, findings, and metadata,
// replacing sensitive values (asset IDs, account IDs) with deterministic
// pseudonyms. [ScrubConfig] selects which field categories to redact, and
// [Policy] enforces sanitization rules across output artifacts.
package sanitize
