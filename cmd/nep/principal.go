package nep

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/iam"
)

type principalOpts struct {
	Snapshot      string
	PrincipalARN  string
	Format        string
	ShowDenied    bool
	ShowChains    bool
	FilterService string
}

func newPrincipalCmd() *cobra.Command {
	opts := &principalOpts{Format: "table"}

	cmd := &cobra.Command{
		Use:   "principal",
		Short: "Resolve permissions for a specific principal ARN",
		Long: `Resolve and display the net effective permissions for a single IAM
principal after all policy layers are applied.

Shows: effective allows, SCP ceiling, permission boundary constraint,
role chains, and privilege classification.

Exit Codes:
  0   Resolution complete, no critical findings
  1   Principal has admin-equivalent or escalation findings
  3   Incomplete resolution (snapshot data missing)
  4   Internal error

Examples:
  stave nep principal --snapshot obs.json \
    --principal arn:aws:iam::123456789012:role/data-pipeline

  stave nep principal --snapshot obs.json \
    --principal arn:aws:iam::123456789012:role/app \
    --format json --show-chains`,
		Example: `  stave nep principal --snapshot obs.json --principal arn:aws:iam::123:role/app`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPrincipal(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.PrincipalARN, "principal", "", "principal ARN to resolve (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().BoolVar(&opts.ShowDenied, "show-denied", false, "include denied actions")
	cmd.Flags().BoolVar(&opts.ShowChains, "show-chains", false, "include role chain detail")
	cmd.Flags().StringVar(&opts.FilterService, "filter-service", "", "filter to a specific service prefix")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("principal")

	return cmd
}

func runPrincipal(opts *principalOpts) error {
	// For this iteration, the command demonstrates the resolution interface.
	// Full snapshot loading integration deferred to when the assessor
	// enrichment pipeline is wired (Step 5 of the Iteration 1 Mikado).
	//
	// The command structure, flag parsing, and output formatting are
	// production-ready. The resolver call uses a stub until the enrichment
	// pipeline provides computed properties.

	if _, err := os.Stat(opts.Snapshot); err != nil {
		return fmt.Errorf("snapshot file not found: %s", opts.Snapshot)
	}

	// Stub: in production, this loads the snapshot and calls the resolver.
	// The PolicyResolver (internal/core/iam/) is implemented — the wiring
	// through the assessor enrichment pipeline connects them.
	result := iam.ResolvedPermissions{
		PrincipalARN:   opts.PrincipalARN,
		PrivilegeLevel: iam.PrivilegeLevelNone,
		Incomplete:     true,
		IncompleteReasons: []string{
			"NEP resolution requires assessor enrichment pipeline integration",
		},
	}

	switch opts.Format {
	case "json":
		return renderPrincipalJSON(result)
	default:
		return renderPrincipalTable(result, opts)
	}
}

func renderPrincipalJSON(result iam.ResolvedPermissions) error {
	out := map[string]any{
		"principal_arn":   result.PrincipalARN,
		"privilege_level": string(result.PrivilegeLevel),
		"is_admin":        result.IsAdmin,
		"incomplete":      result.Incomplete,
	}
	if result.Incomplete {
		out["incomplete_reasons"] = result.IncompleteReasons
	}
	if len(result.EffectiveAllow) > 0 {
		allows := make([]map[string]string, len(result.EffectiveAllow))
		for i, a := range result.EffectiveAllow {
			allows[i] = map[string]string{
				"action":         a.Action,
				"resource_scope": a.Resource,
				"source":         a.Source,
			}
		}
		out["effective_allow"] = allows
	}
	if len(result.SCPBlocked) > 0 {
		out["scp_ceiling"] = result.SCPBlocked
	}
	if len(result.BoundaryBlocked) > 0 {
		out["boundary_ceiling"] = result.BoundaryBlocked
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderPrincipalTable(result iam.ResolvedPermissions, opts *principalOpts) error {
	fmt.Printf("Principal: %s\n", result.PrincipalARN)
	fmt.Printf("Privilege level: %s\n", strings.ToUpper(string(result.PrivilegeLevel)))

	if result.Incomplete {
		fmt.Println("\nRESOLUTION INCOMPLETE")
		for _, reason := range result.IncompleteReasons {
			fmt.Printf("  - %s\n", reason)
		}
		return nil
	}

	if len(result.EffectiveAllow) > 0 {
		fmt.Println("\nEFFECTIVE PERMISSIONS")
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("%-30s %-25s %s\n", "Action", "Resource scope", "Source")
		fmt.Println(strings.Repeat("-", 70))
		for _, a := range result.EffectiveAllow {
			action := a.Action
			if opts.FilterService != "" && !strings.HasPrefix(action, opts.FilterService+":") {
				continue
			}
			resource := truncateARN(a.Resource, 25)
			fmt.Printf("%-30s %-25s %s\n", action, resource, a.Source)
		}
	}

	if opts.ShowDenied && len(result.ExplicitDeny) > 0 {
		fmt.Println("\nEXPLICIT DENIES")
		fmt.Println(strings.Repeat("-", 70))
		for _, d := range result.ExplicitDeny {
			fmt.Printf("  %s on %s (%s)\n", d.Action, d.Resource, d.Source)
		}
	}

	if len(result.SCPBlocked) > 0 {
		fmt.Printf("\nSCP CEILING (%d actions blocked)\n", len(result.SCPBlocked))
		fmt.Println(strings.Repeat("-", 70))
		for _, a := range result.SCPBlocked {
			fmt.Printf("  %s\n", a)
		}
	}

	if opts.ShowChains && len(result.RoleChains) > 0 {
		fmt.Printf("\nROLE CHAINS (%d found)\n", len(result.RoleChains))
		fmt.Println(strings.Repeat("-", 70))
		for i, chain := range result.RoleChains {
			var hops []string
			for _, h := range chain.Hops {
				suffix := ""
				if h.IsCrossAccount {
					suffix = " [cross-account]"
				}
				hops = append(hops, shortARN(h.ToARN)+suffix)
			}
			fmt.Printf("Chain %d (depth %d): %s → %s\n",
				i+1, len(chain.Hops),
				shortARN(result.PrincipalARN),
				strings.Join(hops, " → "))
		}
	}

	return nil
}

func truncateARN(arn string, maxLen int) string {
	if len(arn) <= maxLen {
		return arn
	}
	return arn[:maxLen-3] + "..."
}

func shortARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return arn
}
