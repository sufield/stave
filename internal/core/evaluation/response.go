package evaluation

// ActionSeverity classifies the urgency of a response to an evaluation result.
type ActionSeverity string

// ActionPass and related constants.
const (
	// ActionPass constants.
	ActionPass ActionSeverity = "pass"
	ActionWarn ActionSeverity = "warn"
	ActionFail ActionSeverity = "fail"
)

// ResponseAction describes what a consumer should do given an evaluation outcome.
type ResponseAction struct {
	Severity ActionSeverity
}

// ResponsePolicy maps security states to response actions.
// TreatAtRiskAsFailure causes AT_RISK to be treated as a failure
// (useful for CI pipelines that require a clean bill of health).
type ResponsePolicy struct {
	TreatAtRiskAsFailure bool
}

// Decide returns the appropriate response action for the given security state.
func (p ResponsePolicy) Decide(state SecurityState) ResponseAction {
	switch state {
	case StateCompliant:
		return ResponseAction{Severity: ActionPass}
	case StateAtRisk:
		if p.TreatAtRiskAsFailure {
			return ResponseAction{Severity: ActionFail}
		}
		return ResponseAction{Severity: ActionWarn}
	default:
		return ResponseAction{Severity: ActionFail}
	}
}
