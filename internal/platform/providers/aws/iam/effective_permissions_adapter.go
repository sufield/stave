package iam

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/ports"
)

// EffectivePermissionResolver implements
// [ports.EffectivePermissionResolver] for AWS by wrapping the
// existing [ResolveAllPrincipals] entry point. It is a thin
// adapter — every grant the resolver produces becomes one
// [ports.EffectivePermission] tuple; conditions are stringified
// to the operator:key=value form already used by the SIR
// projector for has_condition_value emission so downstream Z3
// queries see the same vocabulary in both the SIR and the
// PolicyExport.
//
// Zero-value usage: an `iam.EffectivePermissionResolver{}`
// requires no configuration. The adapter is stateless; callers
// can keep one instance for the process lifetime.
type EffectivePermissionResolver struct{}

// NewEffectivePermissionResolver returns a zero-configuration
// resolver. Provided as a constructor for symmetry with the
// other AWS adapters in this package; the underlying type is
// intentionally an empty struct.
func NewEffectivePermissionResolver() *EffectivePermissionResolver {
	return &EffectivePermissionResolver{}
}

// ResolveSnapshot walks every principal in the snapshot, runs
// the per-principal Resolve, and emits one
// [ports.EffectivePermission] per (principal, action, resource)
// pair in the principal's EffectiveAllow set plus
// ResourcePolicyGrants. Output is sorted by
// (PrincipalID, Source, Action, Resource) so byte-identical
// input produces byte-identical output across runs.
//
// nil snapshot returns nil (matching the port contract — the
// caller distinguishes nil from empty-slice). An empty principal
// set returns nil; resolving zero principals is identical to
// "the snapshot is processable but yields no permissions".
func (r *EffectivePermissionResolver) ResolveSnapshot(snap *asset.Snapshot) []ports.EffectivePermission {
	if snap == nil {
		return nil
	}
	resolved, _ := ResolveAllPrincipals(snap)
	if len(resolved) == 0 {
		return nil
	}

	// Pre-collect into a deterministic slice. Map iteration in
	// Go is randomised; the port contract requires stable order.
	out := make([]ports.EffectivePermission, 0, len(resolved)*4)
	for principalID, perms := range resolved {
		if perms == nil {
			continue
		}
		for i := range perms.EffectiveAllow {
			g := &perms.EffectiveAllow[i]
			out = append(out, ports.EffectivePermission{
				PrincipalID: principalID,
				Action:      g.Action,
				Resource:    g.Resource,
				Source:      "identity_policy",
				PolicyARN:   g.Source,
				Conditions:  stringifyConditions(g.Conditions),
			})
		}
		// ResourcePolicyGrant carries (resource, []actions); emit
		// one EffectivePermission per (principal, resource, action)
		// tuple so the port shape stays uniform with the
		// identity-policy case. Cross-account / public flags are
		// carried as synthetic conditions so a downstream Z3 query
		// asking "is this access cross-account?" reads it from the
		// same field as a real policy condition.
		for i := range perms.ResourcePolicyGrants {
			g := &perms.ResourcePolicyGrants[i]
			var conds []string
			if g.IsCrossAccount {
				conds = append(conds, "synthetic:is_cross_account=true")
			}
			if g.IsPublic {
				conds = append(conds, "synthetic:is_public=true")
			}
			for _, action := range g.Actions {
				out = append(out, ports.EffectivePermission{
					PrincipalID: principalID,
					Action:      action,
					Resource:    g.ResourceARN,
					Source:      "resource_policy",
					Conditions:  conds,
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := &out[i], &out[j]
		if a.PrincipalID != b.PrincipalID {
			return a.PrincipalID < b.PrincipalID
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Resource < b.Resource
	})
	return out
}

// stringifyConditions flattens an AWS Condition block (which
// arrives as a nested map[string]map[string]any) into a sorted
// list of "operator:key=value" strings — the same shape the SIR
// projector emits as has_condition_value triples. Returning nil
// for unconditioned grants matches the port's omitempty contract.
//
// Multi-value condition entries (StringEquals: { aws:Tag/team:
// [data, ml] }) flatten to one string per value so each scope
// dimension is independently filterable by downstream Z3
// queries.
func stringifyConditions(raw any) []string {
	if raw == nil {
		return nil
	}
	cond, ok := raw.(map[string]any)
	if !ok || len(cond) == 0 {
		return nil
	}
	var out []string
	for op, keysRaw := range cond {
		keys, ok := keysRaw.(map[string]any)
		if !ok {
			continue
		}
		for k, vRaw := range keys {
			for _, v := range coerceValueList(vRaw) {
				out = append(out, fmt.Sprintf("%s:%s=%s", op, k, v))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func coerceValueList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	// Best-effort: anything else stringifies via fmt.
	return []string{strings.TrimSpace(fmt.Sprintf("%v", v))}
}
