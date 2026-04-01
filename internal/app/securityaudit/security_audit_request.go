package securityaudit

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/core/securityaudit"
)

// Request defines all inputs for a full enterprise audit run.
type Request struct {
	Now                  time.Time
	StaveVersion         string
	Cwd                  string
	BinaryPath           string
	OutDir               string
	SeverityFilter       []securityaudit.Severity
	SBOMFormat           evidence.SBOMFormat
	ComplianceFrameworks []string
	VulnSource           evidence.VulnSource
	LiveVulnCheck        bool
	ReleaseBundleDir     string
	PrivacyEnabled       bool
	FailOn               securityaudit.Severity
	RequireOffline       bool
}

// RequestOption configures a Request.
type RequestOption func(*Request)

// WithNow overrides the audit timestamp (default: time.Now().UTC()).
func WithNow(t time.Time) RequestOption {
	return func(r *Request) { r.Now = t }
}

// WithStaveVersion sets the stave binary version for the audit report.
func WithStaveVersion(v string) RequestOption {
	return func(r *Request) { r.StaveVersion = v }
}

// WithCwd sets the working directory (default: ".").
func WithCwd(dir string) RequestOption {
	return func(r *Request) { r.Cwd = dir }
}

// WithBinaryPath sets the path to the stave binary for inspection.
func WithBinaryPath(path string) RequestOption {
	return func(r *Request) { r.BinaryPath = path }
}

// WithOutDir overrides the audit output directory.
func WithOutDir(dir string) RequestOption {
	return func(r *Request) { r.OutDir = dir }
}

// WithSeverityFilter sets which severity levels to include.
func WithSeverityFilter(levels []securityaudit.Severity) RequestOption {
	return func(r *Request) { r.SeverityFilter = levels }
}

// WithSBOMFormat sets the SBOM output format (default: spdx).
func WithSBOMFormat(f evidence.SBOMFormat) RequestOption {
	return func(r *Request) { r.SBOMFormat = f }
}

// WithComplianceFrameworks sets the compliance frameworks to map.
func WithComplianceFrameworks(frameworks []string) RequestOption {
	return func(r *Request) { r.ComplianceFrameworks = frameworks }
}

// WithVulnSource sets the vulnerability evidence strategy (default: hybrid).
func WithVulnSource(src evidence.VulnSource) RequestOption {
	return func(r *Request) { r.VulnSource = src }
}

// WithLiveVulnCheck enables live vulnerability scanning.
func WithLiveVulnCheck(enabled bool) RequestOption {
	return func(r *Request) { r.LiveVulnCheck = enabled }
}

// WithReleaseBundleDir sets the release bundle directory for evidence.
func WithReleaseBundleDir(dir string) RequestOption {
	return func(r *Request) { r.ReleaseBundleDir = dir }
}

// WithPrivacy enables privacy mode for the audit.
func WithPrivacy(enabled bool) RequestOption {
	return func(r *Request) { r.PrivacyEnabled = enabled }
}

// WithFailOn sets the severity threshold for gating (default: HIGH).
func WithFailOn(sev securityaudit.Severity) RequestOption {
	return func(r *Request) { r.FailOn = sev }
}

// WithRequireOffline enforces offline mode during the audit.
func WithRequireOffline(offline bool) RequestOption {
	return func(r *Request) { r.RequireOffline = offline }
}

// NewRequest creates a Request with sensible defaults, then applies options.
func NewRequest(opts ...RequestOption) Request {
	req := Request{
		Now:          time.Now().UTC(),
		StaveVersion: "unknown",
		Cwd:          ".",
		SBOMFormat:   evidence.SBOMFormatSPDX,
		VulnSource:   evidence.VulnSourceHybrid,
		FailOn:       securityaudit.SeverityHigh,
		SeverityFilter: []securityaudit.Severity{
			securityaudit.SeverityCritical,
			securityaudit.SeverityHigh,
		},
	}
	for _, opt := range opts {
		opt(&req)
	}
	// Normalize formats after options are applied.
	req.SBOMFormat = evidence.SBOMFormat(strings.ToLower(strings.TrimSpace(string(req.SBOMFormat))))
	req.VulnSource = evidence.VulnSource(strings.ToLower(strings.TrimSpace(string(req.VulnSource))))
	if strings.TrimSpace(req.OutDir) == "" {
		req.OutDir = fmt.Sprintf("security-audit-%s", req.Now.UTC().Format("20060102T150405Z"))
	}
	return req
}

func validateRequest(req Request) error {
	if req.SBOMFormat != evidence.SBOMFormatSPDX && req.SBOMFormat != evidence.SBOMFormatCycloneDX {
		return fmt.Errorf("invalid SBOM format %q (use spdx or cyclonedx)", req.SBOMFormat)
	}
	switch req.VulnSource {
	case evidence.VulnSourceHybrid, evidence.VulnSourceLocal, evidence.VulnSourceCI:
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
