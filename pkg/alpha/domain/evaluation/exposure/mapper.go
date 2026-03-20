package exposure

import (
	"github.com/sufield/stave/internal/pkg/maps"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// FactsFromStorage extracts prefix exposure facts from storage properties.
func FactsFromStorage(props map[string]any) Facts {
	pe := maps.ParseMap(props).GetPath("storage.prefix_exposure")
	if pe.IsMissing() {
		return Facts{}
	}

	return Facts{
		HasIdentityEvidence: pe.Get("has_identity_evidence").Bool(),
		HasResourceEvidence: pe.Get("has_resource_evidence").Bool(),

		IdentityGrants:      buildGrants(pe),
		IdentityReadBlocked: pe.Get("identity_read_blocked").Bool(),

		ResourceReadAll:     pe.Get("resource_read_all").Bool(),
		ResourceReadBlocked: pe.Get("resource_read_blocked").Bool(),
	}
}

// buildGrants maps parallel property structures into a slice of Grant objects.
func buildGrants(pe maps.Value) Grants {
	scopes := pe.Get("identity_read_scopes").StringSlice()
	sources := pe.Get("identity_source_by_scope").StringMap()

	if len(scopes) == 0 {
		return nil
	}

	grants := make(Grants, 0, len(scopes))
	for _, scope := range scopes {
		grants = append(grants, Grant{
			Scope:    kernel.ObjectPrefix(scope),
			SourceID: kernel.StatementID(sources[scope]),
		})
	}
	return grants
}
