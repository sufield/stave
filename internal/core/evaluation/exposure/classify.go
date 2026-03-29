package exposure

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// ValidateControlIDs checks that all exposure control IDs conform to the
// required format. Call this during bootstrap instead of relying on
// init()-time panics. IDs are enumerated from the single source of truth
// in control_ids.go.
func ValidateControlIDs() error {
	for _, id := range exposureIDs.all() {
		if err := kernel.ValidateControlIDFormat(id.String()); err != nil {
			return fmt.Errorf("invalid exposure control ID %q: %w", id, err)
		}
	}
	return nil
}

// ClassifyExposure evaluates a set of normalized resource states and returns
// classified risk findings.
func ClassifyExposure(resources []NormalizedResourceInput) []ExposureClassification {
	if len(resources) == 0 {
		return nil
	}

	var findings []ExposureClassification
	for _, r := range resources {
		findings = append(findings, classifyResource(r)...)
	}

	// Sort findings deterministically: by Resource ID, then by Control ID severity.
	slices.SortFunc(findings, func(a, b ExposureClassification) int {
		if a.Resource != b.Resource {
			return strings.Compare(a.Resource, b.Resource)
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})

	return findings
}

func classifyResource(r NormalizedResourceInput) []ExposureClassification {
	// 1. Check for Resource Takeover (Dangling Reference)
	if !r.Exists && r.ExternalReference {
		return []ExposureClassification{{
			ID:             exposureIDs.resourceTakeover,
			Resource:       r.Name,
			ExposureType:   TypeResourceTakeover,
			PrincipalScope: kernel.ScopeNotApplicable,
			Actions:        []string{},
			EvidencePath:   []string{"resource.exists", "resource.external_reference"},
		}}
	}

	// 2. Build Analysis Context
	ctx := resolutionContext{
		input:         r,
		identityPerms: capabilitySetFromMask(r.IdentityPerms),
		resourcePerms: capabilitySetFromMask(r.ResourcePerms),
		isAuthOnly:    r.IsAuthenticatedOnly,
		evidence:      r.Evidence,
		writeSourceStat: writeSourceMetadata{
			CanAlsoRead: r.WriteSourceHasGet,
			CanAlsoList: r.WriteSourceHasList,
		},
	}

	// 3. Resolve Risks across different capability axes
	var findings []ExposureClassification
	findings = append(findings, ctx.resolveRead()...)
	findings = append(findings, ctx.resolveList()...)
	findings = append(findings, ctx.resolveWrite()...)
	findings = append(findings, ctx.resolveAdministrative()...)

	return findings
}
