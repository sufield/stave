// Package diag provides security finding tracking across validation and
// evaluation flows.
//
// [Finding] carries a rule ID, severity level (error/warning/info), human message,
// suggested action, and optional resource context. [Assessment] aggregates multiple
// findings. [Translator] converts domain errors into structured findings using
// the rule ID constants defined in this package.
package diag
