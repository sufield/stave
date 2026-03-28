package securityaudit

import "github.com/sufield/stave/internal/core/securityaudit"

// findingSpec defines the static metadata for a check that follows the
// standard 3-path pattern: error → warn/fail, condition true → pass,
// condition false → fail/warn.
type findingSpec struct {
	ID       securityaudit.CheckID
	Pillar   securityaudit.Pillar
	Severity securityaudit.Severity

	// Error path (err != nil).
	ErrStatus securityaudit.Status // typically StatusWarn
	ErrTitle  string
	ErrHint   string
	ErrReco   string

	// Pass path (condition met).
	PassTitle   string
	PassDetails string
	PassHint    string
	PassReco    string

	// Fail path (condition not met).
	FailStatus  securityaudit.Status // typically StatusFail
	FailTitle   string
	FailDetails string
	FailHint    string
	FailReco    string
}

// buildFinding produces a finding from a spec using the standard 3-path pattern.
// If err is non-nil, the error path is taken with err.Error() as details.
// If pass is true, the pass path is taken.
// Otherwise the fail path is taken.
func buildFinding(spec findingSpec, err error, pass bool, passDetails, failDetails string) securityaudit.Finding {
	base := securityaudit.Finding{
		ID:       spec.ID,
		Pillar:   spec.Pillar,
		Severity: spec.Severity,
	}

	if err != nil {
		base.Status = spec.ErrStatus
		base.Title = spec.ErrTitle
		base.Details = err.Error()
		base.AuditorHint = spec.ErrHint
		base.Recommendation = spec.ErrReco
		return base
	}

	if pass {
		base.Status = securityaudit.StatusPass
		base.Title = spec.PassTitle
		base.Details = passDetails
		if base.Details == "" {
			base.Details = spec.PassDetails
		}
		base.AuditorHint = spec.PassHint
		base.Recommendation = spec.PassReco
		return base
	}

	base.Status = spec.FailStatus
	base.Title = spec.FailTitle
	base.Details = failDetails
	if base.Details == "" {
		base.Details = spec.FailDetails
	}
	base.AuditorHint = spec.FailHint
	base.Recommendation = spec.FailReco
	return base
}
