package nep

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
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
		Example:       `  stave nep principal --snapshot obs.json --principal arn:aws:iam::123:role/app`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPrincipal(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.PrincipalARN, "principal", "", "principal ARN to resolve (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().BoolVar(&opts.ShowDenied, "show-denied", false, "include denied actions")
	cmd.Flags().BoolVar(&opts.ShowChains, "show-chains", false, "include role chain detail")
	cmd.Flags().StringVar(&opts.FilterService, "filter-service", "", "filter to a specific service prefix")

	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "principal")

	return cmd
}

func runPrincipal(w io.Writer, opts *principalOpts) error {
	snaps, err := loadSnapshots(opts.Snapshot)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no snapshots in %s", opts.Snapshot)
	}
	snap := &snaps[len(snaps)-1]

	// Find the target principal in snapshot identities.
	var targetIdentity *identityRef
	for i := range snap.Identities {
		if string(snap.Identities[i].ID) == opts.PrincipalARN {
			targetIdentity = &identityRef{identity: &snap.Identities[i]}
			break
		}
	}

	// Fall back to assets (IAM roles appear in assets too).
	if targetIdentity == nil {
		for i := range snap.Assets {
			if string(snap.Assets[i].ID) == opts.PrincipalARN {
				targetIdentity = &identityRef{asset: &snap.Assets[i]}
				break
			}
		}
	}

	if targetIdentity == nil {
		return fmt.Errorf("principal %s not found in snapshot", opts.PrincipalARN)
	}

	// Resolve the target principal.
	input := targetIdentity.toResolutionInput()
	result := iam.Resolve(input)

	// Resolve all principals for chain analysis.
	if opts.ShowChains {
		resolvedIndex, trustPolicies := iam.ResolveAllPrincipals(snap)
		chains := iam.ResolveChains(iam.RoleChainInput{
			PrincipalARN:  opts.PrincipalARN,
			ResolvedIndex: resolvedIndex,
			TrustPolicies: trustPolicies,
			AccountID:     iam.ExtractAccountIDFromARN(opts.PrincipalARN),
		})
		result.RoleChains = chains
		result.HasTransitiveAdmin = iam.HasTransitiveAdmin(chains)
		if len(chains) > 0 {
			result.MaxChainDepthVal = iam.MaxDepth(chains)
		}
	}

	switch opts.Format {
	case "json":
		return renderPrincipalJSON(w, result)
	default:
		return renderPrincipalTable(w, result, opts)
	}
}

// identityRef wraps either a CloudIdentity or Asset for resolution input.
type identityRef struct {
	identity *asset.CloudIdentity
	asset    *asset.Asset
}

func (r *identityRef) toResolutionInput() iam.ResolutionInput {
	if r.identity != nil {
		return iam.BuildResolutionInput(r.identity)
	}
	// Build from asset properties (IAM roles in assets array).
	return iam.ResolutionInput{
		PrincipalARN: string(r.asset.ID),
		// Assets typically don't carry full policy JSON — resolution
		// will be incomplete but shows what data is available.
	}
}

func renderPrincipalJSON(w io.Writer, result iam.ResolvedPermissions) error {
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderPrincipalTable(w io.Writer, result iam.ResolvedPermissions, opts *principalOpts) error {
	fmt.Fprintf(w, "Principal: %s\n", result.PrincipalARN)
	fmt.Fprintf(w, "Privilege level: %s\n", strings.ToUpper(string(result.PrivilegeLevel)))

	if result.Incomplete {
		fmt.Fprintln(w, "\nRESOLUTION INCOMPLETE")
		for _, reason := range result.IncompleteReasons {
			fmt.Fprintf(w, "  - %s\n", reason)
		}
		return nil
	}

	if len(result.EffectiveAllow) > 0 {
		fmt.Fprintln(w, "\nEFFECTIVE PERMISSIONS")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		fmt.Fprintf(w, "%-30s %-25s %s\n", "Action", "Resource scope", "Source")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for _, a := range result.EffectiveAllow {
			action := a.Action
			if opts.FilterService != "" && !strings.HasPrefix(action, opts.FilterService+":") {
				continue
			}
			resource := truncateARN(a.Resource, 25)
			fmt.Fprintf(w, "%-30s %-25s %s\n", action, resource, a.Source)
		}
	}

	if opts.ShowDenied && len(result.ExplicitDeny) > 0 {
		fmt.Fprintln(w, "\nEXPLICIT DENIES")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for _, d := range result.ExplicitDeny {
			fmt.Fprintf(w, "  %s on %s (%s)\n", d.Action, d.Resource, d.Source)
		}
	}

	if len(result.SCPBlocked) > 0 {
		fmt.Fprintf(w, "\nSCP CEILING (%d actions blocked)\n", len(result.SCPBlocked))
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for _, a := range result.SCPBlocked {
			fmt.Fprintf(w, "  %s\n", a)
		}
	}

	if opts.ShowChains && len(result.RoleChains) > 0 {
		fmt.Fprintf(w, "\nROLE CHAINS (%d found)\n", len(result.RoleChains))
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for i, chain := range result.RoleChains {
			var hops []string
			for _, h := range chain.Hops {
				suffix := ""
				if h.IsCrossAccount {
					suffix = " [cross-account]"
				}
				hops = append(hops, shortARN(h.ToARN)+suffix)
			}
			fmt.Fprintf(w, "Chain %d (depth %d): %s → %s\n",
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
