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
