package exposure

import (
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Priority levels for exposure findings (higher is more severe).
const (
	priorityWebsitePublic = 400
	priorityAuthOnly      = 300
	priorityPolicyRead    = 200
	priorityACLRead       = 100
	priorityPolicyWrite   = 200
	priorityACLWrite      = 100
)

type exposureCandidate struct {
	priority int
	finding  ExposureClassification
}

// updateCandidate sets *c to the new finding if the new priority is higher.
func updateCandidate(c **exposureCandidate, priority int, finding ExposureClassification) {
	if *c == nil || priority > (*c).priority {
		*c = &exposureCandidate{
			priority: priority,
			finding:  finding,
		}
	}
}

type readExposureInput struct {
	bucketName           string
	bucketWebsiteEnabled bool
	isGlobalGet          bool
	writeAbsorbsRead     bool
	isAuthenticatedOnly  bool
	isPolicyGet          bool
	isACLGet             bool
	principalScope       kernel.PrincipalScope
	readEvidence         []string
	policyReadEvidence   []string
	aclReadEvidence      []string
}

func selectReadExposureCandidate(in readExposureInput) *exposureCandidate {
	if !in.isGlobalGet || in.writeAbsorbsRead {
		return nil
	}

	var best *exposureCandidate

	if in.bucketWebsiteEnabled {
		evidence := in.aclReadEvidence
		if in.isPolicyGet {
			evidence = in.readEvidence
		}

		updateCandidate(&best, priorityWebsitePublic, ExposureClassification{
			ID:             exposureIDWebsitePublic,
			Bucket:         in.bucketName,
			ExposureType:   "website_public",
			PrincipalScope: in.principalScope,
			Actions:        []string{outputGetObject},
			EvidencePath:   append(slices.Clone([]string{"bucket.website.enabled"}), evidence...),
		})
	}

	if in.isAuthenticatedOnly {
		updateCandidate(&best, priorityAuthOnly, ExposureClassification{
			ID:             exposureIDGlobalAuthenticatedRead,
			Bucket:         in.bucketName,
			ExposureType:   "authenticated_read",
			PrincipalScope: in.principalScope,
			Actions:        []string{outputGetObject},
			EvidencePath:   in.readEvidence,
		})
	}

	if in.isPolicyGet {
		updateCandidate(&best, priorityPolicyRead, ExposureClassification{
			ID:             exposureIDPublicRead,
			Bucket:         in.bucketName,
			ExposureType:   "public_read",
			PrincipalScope: in.principalScope,
			Actions:        []string{outputGetObject},
			EvidencePath:   in.policyReadEvidence,
		})
	}

	if in.isACLGet {
		updateCandidate(&best, priorityACLRead, ExposureClassification{
			ID:             exposureIDACLPublicRead,
			Bucket:         in.bucketName,
			ExposureType:   "acl_public_read",
			PrincipalScope: in.principalScope,
			Actions:        []string{outputGetObject},
			EvidencePath:   in.aclReadEvidence,
		})
	}

	return best
}

type writeExposureInput struct {
	bucketName          string
	isGlobalPut         bool
	isPolicyPut         bool
	isACLPut            bool
	principalScope      kernel.PrincipalScope
	writeScope          string
	policyWriteEvidence []string
	aclWriteEvidence    []string
	hasGetAction        bool
	hasListAction       bool
}

func selectWriteExposureCandidate(in writeExposureInput) *exposureCandidate {
	if !in.isGlobalPut {
		return nil
	}

	var best *exposureCandidate

	if in.isPolicyPut {
		updateCandidate(&best, priorityPolicyWrite, ExposureClassification{
			ID:             exposureIDPublicWrite,
			Bucket:         in.bucketName,
			ExposureType:   "public_write",
			PrincipalScope: in.principalScope,
			WriteScope:     in.writeScope,
			Actions:        buildWriteActions(in.hasGetAction, in.hasListAction),
			EvidencePath:   in.policyWriteEvidence,
		})
	}

	if in.isACLPut {
		updateCandidate(&best, priorityACLWrite, ExposureClassification{
			ID:             exposureIDACLPublicWrite,
			Bucket:         in.bucketName,
			ExposureType:   "acl_public_write",
			PrincipalScope: in.principalScope,
			WriteScope:     in.writeScope,
			Actions:        []string{outputPutObject},
			EvidencePath:   in.aclWriteEvidence,
		})
	}

	return best
}

// buildWriteActions generates a sorted list of permitted actions.
func buildWriteActions(hasGet, hasList bool) []string {
	actions := []string{outputPutObject}
	if hasGet {
		actions = append(actions, outputGetObject)
	}
	if hasList {
		actions = append(actions, outputListBucket)
	}
	slices.Sort(actions)
	return actions
}
