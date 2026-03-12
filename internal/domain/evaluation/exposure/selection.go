package exposure

import (
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Generic exposure types for reporting.
const (
	TypeWebPublic     = "web_public"
	TypeAuthenticated = "authenticated_access"
	TypePublicRead    = "public_read"
	TypePublicWrite   = "public_write"
)

// Priority levels (higher is more severe risk).
const (
	PriorityWebPublic     = 400
	PriorityAuthenticated = 300
	PriorityIdentityRead  = 200
	PriorityResourceRead  = 100
	PriorityIdentityWrite = 200
	PriorityResourceWrite = 100
)

type exposureCandidate struct {
	priority int
	finding  ExposureClassification
}

// updateCandidate sets *c to the new finding if the new priority is higher.
func updateCandidate(c **exposureCandidate, priority int, finding ExposureClassification) {
	if *c == nil || priority > (*c).priority {
		*c = &exposureCandidate{priority: priority, finding: finding}
	}
}

// ReadExposureInput is a normalized snapshot of resource visibility.
type ReadExposureInput struct {
	ResourceID           string
	WebHostingEnabled    bool
	IsExternallyReadable bool
	WriteAbsorbsRead     bool
	IsAuthenticatedOnly  bool
	HasIdentityRead      bool
	HasResourceRead      bool
	PrincipalScope       kernel.PrincipalScope
	EvidenceGeneral      []string
	EvidenceIdentity     []string
	EvidenceResource     []string
	Actions              []string
}

// SelectReadExposure selects the highest-priority read exposure finding.
func SelectReadExposure(in ReadExposureInput) *exposureCandidate {
	if !in.IsExternallyReadable || in.WriteAbsorbsRead {
		return nil
	}

	var best *exposureCandidate

	if in.WebHostingEnabled {
		evidence := in.EvidenceResource
		if in.HasIdentityRead {
			evidence = in.EvidenceGeneral
		}

		updateCandidate(&best, PriorityWebPublic, ExposureClassification{
			ID:             idWebPublic,
			Resource:       in.ResourceID,
			ExposureType:   TypeWebPublic,
			PrincipalScope: in.PrincipalScope,
			Actions:        in.Actions,
			EvidencePath:   append(slices.Clone([]string{"resource.web_hosting.enabled"}), evidence...),
		})
	}

	if in.IsAuthenticatedOnly {
		updateCandidate(&best, PriorityAuthenticated, ExposureClassification{
			ID:             idAuthenticatedRead,
			Resource:       in.ResourceID,
			ExposureType:   TypeAuthenticated,
			PrincipalScope: in.PrincipalScope,
			Actions:        in.Actions,
			EvidencePath:   in.EvidenceGeneral,
		})
	}

	if in.HasIdentityRead {
		updateCandidate(&best, PriorityIdentityRead, ExposureClassification{
			ID:             idPublicRead,
			Resource:       in.ResourceID,
			ExposureType:   TypePublicRead,
			PrincipalScope: in.PrincipalScope,
			Actions:        in.Actions,
			EvidencePath:   in.EvidenceIdentity,
		})
	}

	if in.HasResourceRead {
		updateCandidate(&best, PriorityResourceRead, ExposureClassification{
			ID:             idResourcePublicRead,
			Resource:       in.ResourceID,
			ExposureType:   TypePublicRead,
			PrincipalScope: in.PrincipalScope,
			Actions:        in.Actions,
			EvidencePath:   in.EvidenceResource,
		})
	}

	return best
}

// WriteExposureInput is a normalized snapshot of resource write-ability.
type WriteExposureInput struct {
	ResourceID       string
	IsPubliclyWrite  bool
	HasIdentityWrite bool
	HasResourceWrite bool
	PrincipalScope   kernel.PrincipalScope
	WriteScope       string
	EvidenceIdentity []string
	EvidenceResource []string
	CanAlsoRead      bool
	CanAlsoList      bool
	BaseActions      []string
}

// SelectWriteExposure selects the highest-priority write exposure finding.
func SelectWriteExposure(in WriteExposureInput) *exposureCandidate {
	if !in.IsPubliclyWrite {
		return nil
	}

	var best *exposureCandidate

	actions := buildEffectiveActions(in.BaseActions, in.CanAlsoRead, in.CanAlsoList)

	if in.HasIdentityWrite {
		updateCandidate(&best, PriorityIdentityWrite, ExposureClassification{
			ID:             idPublicWrite,
			Resource:       in.ResourceID,
			ExposureType:   TypePublicWrite,
			PrincipalScope: in.PrincipalScope,
			WriteScope:     in.WriteScope,
			Actions:        actions,
			EvidencePath:   in.EvidenceIdentity,
		})
	}

	if in.HasResourceWrite {
		updateCandidate(&best, PriorityResourceWrite, ExposureClassification{
			ID:             idResourcePublicWrite,
			Resource:       in.ResourceID,
			ExposureType:   TypePublicWrite,
			PrincipalScope: in.PrincipalScope,
			WriteScope:     in.WriteScope,
			Actions:        in.BaseActions,
			EvidencePath:   in.EvidenceResource,
		})
	}

	return best
}

func buildEffectiveActions(base []string, canRead, canList bool) []string {
	res := slices.Clone(base)
	if canRead {
		res = append(res, ActionRead)
	}
	if canList {
		res = append(res, ActionList)
	}
	slices.Sort(res)
	return slices.Compact(res)
}
