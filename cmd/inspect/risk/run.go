package risk

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/platform/fsutil"
	domainrisk "github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

// RiskInput is the JSON input for risk analysis.
type RiskInput struct {
	Actions         []string `json:"actions"`
	IsPublic        bool     `json:"is_public"`
	IsAuthenticated bool     `json:"is_authenticated"`
	IsNetworkScoped bool     `json:"is_network_scoped"`
	IsAllow         bool     `json:"is_allow"`
}

// RiskOutput is the JSON output of risk analysis.
type RiskOutput struct {
	NormalizedActions []string              `json:"normalized_actions"`
	Permissions       domainrisk.Permission `json:"permissions"`
	PermissionCheck   PermissionCheck       `json:"permission_check"`
	StatementResult   domainrisk.Result     `json:"statement_result"`
	Report            domainrisk.Report     `json:"report"`
}

// PermissionCheck exercises Permission.Has and Permission.Overlap.
type PermissionCheck struct {
	HasRead       bool `json:"has_read"`
	HasWrite      bool `json:"has_write"`
	OverlapAdmin  bool `json:"overlap_admin"`
	IsFullControl bool `json:"is_full_control"`
}

func run(cmd *cobra.Command, file string) error {
	input, err := readInput(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	var in RiskInput
	if err := json.Unmarshal(input, &in); err != nil {
		return fmt.Errorf("parse risk input: %w", err)
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

	output := RiskOutput{
		NormalizedActions: normalized,
		Permissions:       perms,
		PermissionCheck: PermissionCheck{
			HasRead:       perms.Has(domainrisk.PermRead),
			HasWrite:      perms.Has(domainrisk.PermWrite),
			OverlapAdmin:  perms.Overlap(domainrisk.PermAdminRead | domainrisk.PermAdminWrite),
			IsFullControl: perms == domainrisk.PermFullControl,
		},
		StatementResult: result,
		Report:          report,
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return fsutil.ReadFileLimited(file)
	}
	return io.ReadAll(stdin)
}
