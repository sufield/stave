package evidence

import "github.com/sufield/stave/internal/core/kernel"

// MapVerdict translates an assessment engine verdict string to an
// EvidenceVerdict. Uses shared kernel constants so a verdict rename
// produces a compile error in both packages.
func MapVerdict(v string) EvidenceVerdict {
	switch v {
	case kernel.VerdictViolation:
		return VerdictFail
	case kernel.VerdictPass:
		return VerdictPass
	case kernel.VerdictInconclusive:
		return VerdictIncomplete
	case kernel.VerdictNotApplicable, kernel.VerdictSkipped:
		return VerdictNotApplicable
	default:
		return VerdictNotApplicable
	}
}
