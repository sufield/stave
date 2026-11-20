package template

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/pkg/stave/snapshot"
)

// AutoScope is the resolved control/chain selection for templates
// that use scope: auto. Derived from the intersection of services
// in the snapshot and service prefixes in the control catalog.
type AutoScope struct {
	ControlPatterns []string
	ChainIDs        []string
	MatchedServices []string
	SkippedChains   []string
}

// ControlCatalog abstracts the set of available controls for
// auto-scope resolution. Implementations provide the full set of
// control IDs and chain dependency metadata.
type ControlCatalog interface {
	ControlIDs() []string
	ChainDependencies() map[string][]string // chain ID → required services
}

// ResolveAutoScope derives control selection from the intersection
// of services in the snapshot and service prefixes in the catalog.
func ResolveAutoScope(summary snapshot.Summary, catalog ControlCatalog) (AutoScope, error) {
	catalogPrefixes := extractCatalogPrefixes(catalog.ControlIDs())

	snapshotServices := make(map[string]bool, len(summary.Services))
	for _, svc := range summary.Services {
		snapshotServices[strings.ToLower(svc)] = true
	}

	var scope AutoScope
	for prefix, svc := range catalogPrefixes {
		if snapshotServices[svc] {
			scope.ControlPatterns = append(scope.ControlPatterns, "CTL."+prefix+".*")
			scope.MatchedServices = append(scope.MatchedServices, svc)
		}
	}

	if len(scope.MatchedServices) == 0 {
		catalogServices := make([]string, 0, len(catalogPrefixes))
		seen := make(map[string]bool)
		for _, svc := range catalogPrefixes {
			if !seen[svc] {
				seen[svc] = true
				catalogServices = append(catalogServices, svc)
			}
		}
		return AutoScope{}, fmt.Errorf(
			"no controls match the services in this snapshot\n"+
				"  Services in snapshot: %v\n"+
				"  Control catalog covers: %v",
			summary.Services, catalogServices)
	}

	scope.ChainIDs, scope.SkippedChains = filterChainsByServices(catalog.ChainDependencies(), scope.MatchedServices)

	return scope, nil
}

func filterChainsByServices(chainDeps map[string][]string, matchedServices []string) (matched, skipped []string) {
	matchedSet := make(map[string]bool, len(matchedServices))
	for _, svc := range matchedServices {
		matchedSet[svc] = true
	}
	for chainID, deps := range chainDeps {
		satisfied := true
		for _, dep := range deps {
			if !matchedSet[strings.ToLower(dep)] {
				satisfied = false
				break
			}
		}
		if satisfied {
			matched = append(matched, chainID)
		} else {
			skipped = append(skipped, chainID)
		}
	}
	return
}

// extractCatalogPrefixes scans control IDs and returns a map of
// uppercase prefix → lowercase service name.
// e.g., "CTL.IAM.POLICY.WILDCARD.001" → {"IAM": "iam"}
func extractCatalogPrefixes(controlIDs []string) map[string]string {
	prefixes := make(map[string]string)
	for _, id := range controlIDs {
		parts := strings.SplitN(id, ".", 3)
		if len(parts) < 3 || parts[0] != "CTL" {
			continue
		}
		prefix := parts[1]
		prefixes[prefix] = strings.ToLower(prefix)
	}
	return prefixes
}
