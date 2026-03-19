package apply

import appapply "github.com/sufield/stave/internal/app/apply"

// EvaluateResult provides structured execution outcomes and user guidance.
type EvaluateResult = appapply.EvaluateResult

// BuildEvaluateResult maps a domain safety status into actionable CLI guidance.
var BuildEvaluateResult = appapply.BuildEvaluateResult
