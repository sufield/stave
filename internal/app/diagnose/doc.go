// Package diagnose orchestrates the diagnosis use case.
//
// It loads controls, observation snapshots, and optionally prior evaluation
// results, then delegates to the domain diagnosis engine to produce a
// diagnostic report with root-cause analysis and troubleshooting guidance.
package diagnose
