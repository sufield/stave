// Package diag provides diagnostic issue tracking across validation and
// evaluation flows.
//
// [Diagnostic] carries a code, signal level (error/warning/info), human message,
// suggested action, and optional evidence. [Report] aggregates multiple issues.
// [Translator] converts domain errors into structured diagnostic issues using
// the code constants defined in this package.
package diag
