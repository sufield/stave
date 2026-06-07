package stave

import (
	"bytes"
	"encoding/json"
	"fmt"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
	domainrisk "github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/util/jsonutil"
)

type riskInput struct {
	Actions         []string `json:"actions"`
	IsPublic        bool     `json:"is_public"`
	IsAuthenticated bool     `json:"is_authenticated"`
	IsNetworkScoped bool     `json:"is_network_scoped"`
	IsAllow         bool     `json:"is_allow"`
}

type riskOutput struct {
	NormalizedActions []string                       `json:"normalized_actions"`
	Permissions       domainrisk.Permission          `json:"permissions"`
	PermissionCheck   riskPermissionCheck            `json:"permission_check"`
	StatementResult   domainrisk.StatementAssessment `json:"statement_result"`
	Report            domainrisk.Report              `json:"report"`
}

type riskPermissionCheck struct {
	HasRead       bool `json:"has_read"`
	HasWrite      bool `json:"has_write"`
	OverlapAdmin  bool `json:"overlap_admin"`
	IsFullControl bool `json:"is_full_control"`
}

// InspectRisk parses a policy statement context (JSON) and computes the
// risk score plus permission analysis, returning the report as indented
// JSON bytes. It builds the default permission resolver internally, so it
// is the library entry point behind `stave inspect risk`.
func InspectRisk(input []byte) ([]byte, error) {
	var in riskInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("parse risk input: %w", err)
	}

	normalized := domainrisk.NormalizeActions(in.Actions)
	perms := domainrisk.ResolveActions(normalized, s3resolver.NewResolver())

	ctx := domainrisk.StatementContext{
		Permissions:     perms,
		IsPublic:        in.IsPublic,
		IsAuthenticated: in.IsAuthenticated,
		IsNetworkScoped: in.IsNetworkScoped,
		IsAllow:         in.IsAllow,
	}
	result := ctx.Evaluate()

	report := domainrisk.Report{}
	report.UpdateReport(result)
	report.Permissions = perms

	out := riskOutput{
		NormalizedActions: normalized,
		Permissions:       perms,
		PermissionCheck: riskPermissionCheck{
			HasRead:       perms.Has(domainrisk.PermRead),
			HasWrite:      perms.Has(domainrisk.PermWrite),
			OverlapAdmin:  perms.Overlap(domainrisk.PermAdminRead | domainrisk.PermAdminWrite),
			IsFullControl: perms == domainrisk.PermFullControl,
		},
		StatementResult: result,
		Report:          report,
	}

	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, out); err != nil {
		return nil, fmt.Errorf("encode risk report: %w", err)
	}
	return buf.Bytes(), nil
}
