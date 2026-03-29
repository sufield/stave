package exposure

import (
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// Type represents the category of exposure.
type Type string

const (
	TypeWebPublic        Type = "web_public"
	TypeAuthenticated    Type = "authenticated_access"
	TypePublicRead       Type = "public_read"
	TypePublicWrite      Type = "public_write"
	TypePublicList       Type = "public_list"
	TypePublicMetaRead   Type = "public_metadata_read"
	TypePublicMetaWrite  Type = "public_metadata_write"
	TypePublicDelete     Type = "public_delete"
	TypeResourceTakeover Type = "resource_takeover"
)

// WriteScope represents the scope of write access.
type WriteScope string

const (
	WriteScopeBlind WriteScope = "blind"
	WriteScopeFull  WriteScope = "full"
)

// Priority represents the severity ranking of an exposure finding.
// Higher values indicate more severe risk.
type Priority int

const (
	PriorityResourceRead  Priority = 100
	PriorityResourceWrite Priority = 100
	PriorityIdentityRead  Priority = 200
	PriorityIdentityWrite Priority = 200
	PriorityAuthenticated Priority = 300
	PriorityWebPublic     Priority = 400
)

// exposureCandidate tracks the most severe finding identified during analysis.
type exposureCandidate struct {
	priority Priority
	finding  ExposureClassification
}

// consider updates the candidate if the provided priority is higher than the current one.
func (c *exposureCandidate) consider(priority Priority, f ExposureClassification) {
	if c.finding.ID == "" || priority > c.priority {
		c.priority = priority
		c.finding = f
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

	best := &exposureCandidate{}

	template := func(id kernel.ControlID, t Type, ev []string) ExposureClassification {
		return ExposureClassification{
			ID:             id,
			Resource:       in.ResourceID,
			ExposureType:   t,
			PrincipalScope: in.PrincipalScope,
			Actions:        in.Actions,
			EvidencePath:   ev,
		}
	}

	if in.WebHostingEnabled {
		ev := in.EvidenceResource
		if in.HasIdentityRead {
			ev = in.EvidenceGeneral
		}
		path := append(slices.Clone([]string{"resource.web_hosting.enabled"}), ev...)
		best.consider(PriorityWebPublic, template(exposureIDs.webPublic, TypeWebPublic, path))
	}

	if in.IsAuthenticatedOnly {
		best.consider(PriorityAuthenticated, template(exposureIDs.authenticatedRead, TypeAuthenticated, in.EvidenceGeneral))
	}

	if in.HasIdentityRead {
		best.consider(PriorityIdentityRead, template(exposureIDs.publicRead, TypePublicRead, in.EvidenceIdentity))
	}

	if in.HasResourceRead {
		best.consider(PriorityResourceRead, template(exposureIDs.resourcePublicRead, TypePublicRead, in.EvidenceResource))
	}

	if best.finding.ID == "" {
		return nil
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
	WriteScope       WriteScope
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

	best := &exposureCandidate{}
	actions := buildEffectiveActions(in.BaseActions, in.CanAlsoRead, in.CanAlsoList)

	template := func(id kernel.ControlID, ev []string) ExposureClassification {
		return ExposureClassification{
			ID:             id,
			Resource:       in.ResourceID,
			ExposureType:   TypePublicWrite,
			PrincipalScope: in.PrincipalScope,
			WriteScope:     in.WriteScope,
			Actions:        actions,
			EvidencePath:   ev,
		}
	}

	if in.HasIdentityWrite {
		best.consider(PriorityIdentityWrite, template(exposureIDs.publicWrite, in.EvidenceIdentity))
	}

	if in.HasResourceWrite {
		f := template(exposureIDs.resourcePublicWrite, in.EvidenceResource)
		f.Actions = in.BaseActions
		best.consider(PriorityResourceWrite, f)
	}

	if best.finding.ID == "" {
		return nil
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
