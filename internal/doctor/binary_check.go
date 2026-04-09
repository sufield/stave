package doctor

import (
	"github.com/sufield/stave/internal/core/outcome"
)

// BinaryRequest defines the parameters for validating a system dependency.
type BinaryRequest struct {
	Binary      string
	Name        string
	WarnMessage string
	PassMessage string
	Remediation string
}

// checkBinary verifies if a specific binary is available in the system PATH.
func checkBinary(ctx *SystemEnvironment, req BinaryRequest) Diagnostic {
	if req.Binary == "" {
		return Diagnostic{
			Name:    req.Name,
			Status:  outcome.Fail,
			Message: "Logic error: binary name not specified in check request",
		}
	}

	_, err := ctx.PathLookupFn(req.Binary)
	if err != nil {
		return Diagnostic{
			Name:        req.Name,
			Status:      outcome.Warn,
			Message:     req.WarnMessage,
			Remediation: req.Remediation,
		}
	}

	message := req.PassMessage
	if message == "" {
		message = req.Binary + " is available in PATH"
	}

	return Diagnostic{
		Name:    req.Name,
		Status:  outcome.Pass,
		Message: message,
	}
}
