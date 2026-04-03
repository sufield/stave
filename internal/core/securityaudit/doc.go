// Package securityaudit defines the security-audit report output format.
//
// [Report] and [Finding] model the audit output, while [Pillar]
// and Severity enums classify findings. Finding status uses
// [outcome.Status] from the shared outcome package. [Summary] aggregates
// counts across severity levels for high-level reporting.
package securityaudit
