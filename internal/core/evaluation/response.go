package evaluation

// ActionSeverity classifies the urgency of a response to an evaluation result.
type ActionSeverity string

const (
	ActionPass ActionSeverity = "pass"
	ActionWarn ActionSeverity = "warn"
	ActionFail ActionSeverity = "fail"
)

// ResponseAction describes what a consumer should do given an evaluation outcome.
type ResponseAction struct {
	Severity ActionSeverity
}

// ResponsePolicy maps safety statuses to response actions.
// StrictBorderline causes BORDERLINE to be treated as a failure
// (useful for CI pipelines that require a clean bill of health).
type ResponsePolicy struct {
	StrictBorderline bool
}

// Decide returns the appropriate response action for the given safety status.
func (p ResponsePolicy) Decide(status SafetyStatus) ResponseAction {
	switch status {
	case StatusSafe:
		return ResponseAction{Severity: ActionPass}
	case StatusBorderline:
		if p.StrictBorderline {
			return ResponseAction{Severity: ActionFail}
		}
		return ResponseAction{Severity: ActionWarn}
	default:
		return ResponseAction{Severity: ActionFail}
	}
}
