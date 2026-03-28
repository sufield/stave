package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// SecurityAuditRunnerPort executes the security audit pipeline.
type SecurityAuditRunnerPort interface {
	RunAudit(ctx context.Context, req domain.SecurityAuditRequest) (reportData any, summary domain.SecurityAuditSummary, gated bool, err error)
}

// SecurityAuditDeps groups the port interfaces for the security-audit use case.
type SecurityAuditDeps struct {
	Runner SecurityAuditRunnerPort
}

// SecurityAudit generates enterprise security posture evidence.
func SecurityAudit(
	ctx context.Context,
	req domain.SecurityAuditRequest,
	deps SecurityAuditDeps,
) (domain.SecurityAuditResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityAuditResponse{}, fmt.Errorf("security_audit: %w", err)
	}

	reportData, summary, gated, err := deps.Runner.RunAudit(ctx, req)
	if err != nil {
		return domain.SecurityAuditResponse{}, fmt.Errorf("security_audit: %w", err)
	}

	return domain.SecurityAuditResponse{
		ReportData: reportData,
		Summary:    summary,
		Gated:      gated,
	}, nil
}
