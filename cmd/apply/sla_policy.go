package apply

// SLAPolicy controls whether SLA breaches in an `apply` run cause a
// non-zero exit. The default is "warn" (no exit-code effect).
type SLAPolicy string

const (
	// SLAPolicyWarn lets SLA breaches surface in the output without
	// changing the exit code. The default.
	SLAPolicyWarn SLAPolicy = "warn"
	// SLAPolicyStrict fails (exit 3) on any SLA breach.
	SLAPolicyStrict SLAPolicy = "strict"
	// SLAPolicyCriticalOnly fails (exit 3) only on SLA breaches whose
	// finding (or escalated severity) is critical.
	SLAPolicyCriticalOnly SLAPolicy = "critical-only"
)

// String returns the wire value.
func (p SLAPolicy) String() string { return string(p) }

// FailureMessage returns the operator-facing line printed to stderr
// when this policy gates the apply run to a non-zero exit. Returns
// "" for SLAPolicyWarn (the default never fails) and any
// unrecognised policy value. Centralises the per-policy phrasing so
// Reporter.CheckSLAPolicy stops switching on the policy literal.
func (p SLAPolicy) FailureMessage() string {
	switch p {
	case SLAPolicyStrict:
		return "SLA policy: strict — SLA breach detected, failing."
	case SLAPolicyCriticalOnly:
		return "SLA policy: critical-only — critical SLA breach detected, failing."
	default:
		return ""
	}
}
