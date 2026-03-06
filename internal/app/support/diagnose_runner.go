package support

import (
	"context"
	"fmt"

	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
)

// DiagnoseReportRequest captures the core report execution inputs.
type DiagnoseReportRequest struct {
	Context  context.Context
	Run      *appdiagnose.Run
	Config   appdiagnose.Config
	Sanitize func(*diagnosis.Report) *diagnosis.Report
}

// ExecuteDiagnoseReport runs diagnose and applies optional sanitization.
func ExecuteDiagnoseReport(req DiagnoseReportRequest) (*diagnosis.Report, error) {
	if req.Run == nil {
		return nil, fmt.Errorf("diagnose runner is required")
	}
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	report, err := req.Run.Execute(ctx, req.Config)
	if err != nil {
		return nil, err
	}
	if req.Sanitize != nil {
		report = req.Sanitize(report)
	}
	return report, nil
}
