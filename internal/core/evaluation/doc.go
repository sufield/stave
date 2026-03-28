// Package evaluation contains core types for evaluation execution and output.
//
// The heavy lifting lives in subpackages:
//
//   - [engine]: Timeline processing, finding generation, coverage metrics, and
//     the main [engine.Runner] that orchestrates evaluation across snapshots.
//   - [diagnosis]: Post-evaluation root-cause analysis — streak detection,
//     evidence interpretation, and diagnostic report generation.
//   - [remediation]: Machine-readable remediation plans — baseline/target state
//     calculation, specialist handlers, and plan grouping.
//   - [exposure]: Visibility classification (public, authenticated, private)
//     by combining capability signals with governance overrides.
//   - [risk]: Security-risk scoring (Safe through Catastrophic) and predictive
//     analysis for controls approaching unsafe thresholds.
package evaluation
