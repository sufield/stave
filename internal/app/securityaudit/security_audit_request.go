package securityaudit

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// Request defines all inputs for a full enterprise audit run.
type Request struct {
	Now                  time.Time
	StaveVersion         string
	Cwd                  string
	BinaryPath           string
	OutDir               string
	SeverityFilter       []securityaudit.Severity
	SBOMFormat           SBOMFormat
	ComplianceFrameworks []string
	VulnSource           VulnSource
	LiveVulnCheck        bool
	ReleaseBundleDir     string
	PrivacyEnabled       bool
	FailOn               securityaudit.Severity
	RequireOffline       bool
}

func normalizeRequest(req Request) Request {
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}
	if strings.TrimSpace(req.StaveVersion) == "" {
		req.StaveVersion = "unknown"
	}
	if strings.TrimSpace(req.Cwd) == "" {
		req.Cwd = "."
	}
	if strings.TrimSpace(string(req.SBOMFormat)) == "" {
		req.SBOMFormat = SBOMFormatSPDX
	}
	req.SBOMFormat = SBOMFormat(strings.ToLower(strings.TrimSpace(string(req.SBOMFormat))))
	if strings.TrimSpace(string(req.VulnSource)) == "" {
		req.VulnSource = VulnSourceHybrid
	}
	req.VulnSource = VulnSource(strings.ToLower(strings.TrimSpace(string(req.VulnSource))))
	if req.FailOn == "" {
		req.FailOn = securityaudit.SeverityHigh
	}
	if len(req.SeverityFilter) == 0 {
		req.SeverityFilter = []securityaudit.Severity{
			securityaudit.SeverityCritical,
			securityaudit.SeverityHigh,
		}
	}
	if strings.TrimSpace(req.OutDir) == "" {
		req.OutDir = fmt.Sprintf("security-audit-%s", req.Now.UTC().Format("20060102T150405Z"))
	}
	return req
}

func validateRequest(req Request) error {
	if req.SBOMFormat != SBOMFormatSPDX && req.SBOMFormat != SBOMFormatCycloneDX {
		return fmt.Errorf("invalid SBOM format %q (use spdx or cyclonedx)", req.SBOMFormat)
	}
	switch req.VulnSource {
	case VulnSourceHybrid, VulnSourceLocal, VulnSourceCI:
	default:
		return fmt.Errorf("invalid vulnerability source %q (use hybrid, local, or ci)", req.VulnSource)
	}
	for _, sev := range req.SeverityFilter {
		if _, err := securityaudit.ParseSeverity(string(sev)); err != nil {
			return fmt.Errorf("invalid severity filter value %q: %w", sev, err)
		}
	}
	if req.FailOn != securityaudit.SeverityNone {
		if _, err := securityaudit.ParseSeverity(string(req.FailOn)); err != nil {
			return fmt.Errorf("invalid fail-on value %q: %w", req.FailOn, err)
		}
	}
	return nil
}
