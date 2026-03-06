package exposure

import "github.com/sufield/stave/internal/pkg/maps"

// FactsFromStorage extracts prefix exposure facts from storage properties.
func FactsFromStorage(props map[string]any) Facts {
	pe := maps.ParseMap(props).GetPath("storage.prefix_exposure")
	if pe.IsMissing() {
		return Facts{}
	}

	return Facts{
		HasPolicyEvidence:       pe.Get("has_policy_evidence").Bool(),
		HasACLEvidence:          pe.Get("has_acl_evidence").Bool(),
		PolicyGrants:            BuildGrants(pe.Get("policy_public_read_scopes").StringSlice(), pe.Get("policy_source_by_scope").StringMap()),
		PolicyPublicReadBlocked: pe.Get("policy_public_read_blocked").Bool(),
		ACLPublicReadAll:        pe.Get("acl_public_read_all").Bool(),
		ACLPublicReadBlocked:    pe.Get("acl_public_read_blocked").Bool(),
	}
}

// BuildGrants constructs policy grants from raw scopes and source IDs.
func BuildGrants(scopes []string, sourceByScope map[string]string) Grants {
	if len(scopes) == 0 {
		return nil
	}

	grants := make(Grants, len(scopes))
	for i, scope := range scopes {
		grants[i] = Grant{
			Scope:    scope,
			SourceID: sourceByScope[scope],
		}
	}
	return grants
}
