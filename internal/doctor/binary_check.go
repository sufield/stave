package doctor

// BinaryCheckRequest defines parameters for dependency binary checks.
type BinaryCheckRequest struct {
	BinaryName  string
	CheckName   string
	WarnMessage string
	PassMessage string
	Fix         string
}

func checkBinary(ctx Context, req BinaryCheckRequest) Check {
	if req.BinaryName == "" {
		return Check{Name: req.CheckName, Status: StatusFail, Message: "missing binary name"}
	}

	_, err := ctx.LookPathFn(req.BinaryName)
	if err != nil {
		return Check{
			Name:    req.CheckName,
			Status:  StatusWarn,
			Message: req.WarnMessage,
			Fix:     req.Fix,
		}
	}

	return Check{
		Name:    req.CheckName,
		Status:  StatusPass,
		Message: req.PassMessage,
	}
}
