package nepcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// PrincipalConfig parameterizes [ResolvePrincipal].
type PrincipalConfig struct {
	Snapshot      string
	PrincipalARN  string
	Format        string
	ShowDenied    bool
	ShowChains    bool
	FilterService string
}

// ResolvePrincipal resolves the net effective permissions for a single IAM
// principal and renders them (table | json). A bad format / load failure /
// missing principal stays plain (exit 4).
func ResolvePrincipal(cfg PrincipalConfig) ([]byte, error) {
	snaps, err := loadSnapshots(cfg.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("no snapshots in %s", cfg.Snapshot)
	}
	snap := &snaps[len(snaps)-1]

	// Find the target principal in snapshot identities.
	var targetIdentity *identityRef
	for i := range snap.Identities {
		if string(snap.Identities[i].ID) == cfg.PrincipalARN {
			targetIdentity = &identityRef{identity: &snap.Identities[i]}
			break
		}
	}
	// Fall back to assets (IAM roles appear in assets too).
	if targetIdentity == nil {
		for i := range snap.Assets {
			if string(snap.Assets[i].ID) == cfg.PrincipalARN {
				targetIdentity = &identityRef{asset: &snap.Assets[i]}
				break
			}
		}
	}
	if targetIdentity == nil {
		return nil, fmt.Errorf("principal %s not found in snapshot", cfg.PrincipalARN)
	}

	result := iam.Resolve(targetIdentity.toResolutionInput())

	if cfg.ShowChains {
		resolvedIndex, trustPolicies := iam.ResolveAllPrincipals(snap)
		chains := iam.ResolveChains(iam.RoleChainInput{
			PrincipalARN:  cfg.PrincipalARN,
			ResolvedIndex: resolvedIndex,
			TrustPolicies: trustPolicies,
			AccountID:     iam.ExtractAccountIDFromARN(cfg.PrincipalARN),
		})
		result.RoleChains = chains
		result.HasTransitiveAdmin = iam.HasTransitiveAdmin(chains)
		if len(chains) > 0 {
			result.MaxChainDepthVal = iam.MaxDepth(chains)
		}
	}

	var buf bytes.Buffer
	if err := renderPrincipal(cfg.Format, &buf, result, cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// renderPrincipal dispatches to the format-specific principal renderer.
func renderPrincipal(format string, w io.Writer, result iam.ResolvedPermissions, cfg PrincipalConfig) error {
	switch format {
	case "json":
		return renderPrincipalJSON(w, result)
	case "table", "":
		return renderPrincipalTable(w, result, cfg)
	}
	return fmt.Errorf("unsupported format %q (expected: table | json)", format)
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
	temp := &asset.CloudIdentity{
		ID:         r.asset.ID,
		Type:       r.asset.Type,
		Vendor:     r.asset.Vendor,
		Properties: r.asset.Properties,
	}
	return iam.BuildResolutionInput(temp)
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

func renderPrincipalTable(w io.Writer, result iam.ResolvedPermissions, cfg PrincipalConfig) error {
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
			if cfg.FilterService != "" && !strings.HasPrefix(action, cfg.FilterService+":") {
				continue
			}
			resource := truncateARN(a.Resource, 25)
			fmt.Fprintf(w, "%-30s %-25s %s\n", action, resource, a.Source)
		}
	}

	if cfg.ShowDenied && len(result.ExplicitDeny) > 0 {
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

	if cfg.ShowChains && len(result.RoleChains) > 0 {
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
