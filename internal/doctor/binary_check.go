package doctor

import "fmt"

// BinaryRequest defines the parameters for validating a system dependency.
type BinaryRequest struct {
	Binary      string
	Name        string
	WarnMessage string
	PassMessage string
	Fix         string
}

// checkBinary verifies if a specific binary is available in the system PATH.
func checkBinary(ctx *Context, req BinaryRequest) Check {
	if req.Binary == "" {
		return Check{
			Name:    req.Name,
			Status:  StatusFail,
			Message: "Logic error: binary name not specified in check request",
		}
	}

	_, err := ctx.LookPathFn(req.Binary)
	if err != nil {
		return Check{
			Name:    req.Name,
			Status:  StatusWarn,
			Message: req.WarnMessage,
			Fix:     req.Fix,
		}
	}

	message := req.PassMessage
	if message == "" {
		message = fmt.Sprintf("%s is available in PATH", req.Binary)
	}

	return Check{
		Name:    req.Name,
		Status:  StatusPass,
		Message: message,
	}
}
