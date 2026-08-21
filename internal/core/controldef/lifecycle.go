package controldef

// LifecycleStatus represents where a control sits in its lifecycle.
type LifecycleStatus string

const (
	LifecycleActive      LifecycleStatus = "active"
	LifecycleMaintenance LifecycleStatus = "maintenance"
	LifecycleSunset      LifecycleStatus = "sunset"
	LifecycleEOL         LifecycleStatus = "eol"
)

func (s LifecycleStatus) String() string { return string(s) }

func (s LifecycleStatus) IsValid() bool {
	switch s {
	case LifecycleActive, LifecycleMaintenance, LifecycleSunset, LifecycleEOL:
		return true
	default:
		return false
	}
}

// IsDeprecated reports whether the status represents a control
// whose underlying resource/feature is no longer recommended.
func (s LifecycleStatus) IsDeprecated() bool {
	return s == LifecycleSunset || s == LifecycleEOL
}

// ControlLifecycle carries lifecycle metadata for a control.
// Controls without a lifecycle block default to active.
type ControlLifecycle struct {
	Status    LifecycleStatus `json:"status"`
	Since     string          `json:"since,omitempty"`
	Deadline  string          `json:"deadline,omitempty"`
	Successor string          `json:"successor,omitempty"`
	Reference string          `json:"reference,omitempty"`
}

// IsZero reports whether the lifecycle block was absent from YAML.
func (l ControlLifecycle) IsZero() bool {
	return l.Status == "" && l.Since == "" && l.Deadline == "" && l.Successor == "" && l.Reference == ""
}

// EffectiveStatus returns the lifecycle status, defaulting to active
// when the block is absent.
func (l ControlLifecycle) EffectiveStatus() LifecycleStatus {
	if l.Status == "" {
		return LifecycleActive
	}
	return l.Status
}
