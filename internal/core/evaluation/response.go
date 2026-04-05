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
// TreatBorderlineAsFailure causes BORDERLINE to be treated as a failure
// (useful for CI pipelines that require a clean bill of health).
type ResponsePolicy struct {
	TreatBorderlineAsFailure bool
}

// Decide returns the appropriate response action for the given safety status.
func (p ResponsePolicy) Decide(status Posture) ResponseAction {
	switch status {
	case PostureSafe:
		return ResponseAction{Severity: ActionPass}
	case PostureBorderline:
		if p.TreatBorderlineAsFailure {
			return ResponseAction{Severity: ActionFail}
		}
		return ResponseAction{Severity: ActionWarn}
	default:
		return ResponseAction{Severity: ActionFail}
	}
}
