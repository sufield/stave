package kernel

// Verdict string constants shared between the evaluation and evidence
// packages. Both packages need to agree on these values; placing them
// in kernel lets each import typed constants instead of matching raw
// strings across a package boundary.
const (
	VerdictViolation     = "VIOLATION"
	VerdictPass          = "PASS"
	VerdictInconclusive  = "INCONCLUSIVE"
	VerdictNotApplicable = "NOT_APPLICABLE"
	VerdictSkipped       = "SKIPPED"
)
