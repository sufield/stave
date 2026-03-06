package exposure

import (
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

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

// candidateRequest bundles the parameters required to build an exposure finding.
type candidateRequest struct {
	Priority       int
	ID             kernel.ControlID
	ExposureType   string
	Actions        []string
	Evidence       []string
	BucketName     string
	PrincipalScope kernel.PrincipalScope
	WriteScope     string
}

// buildCandidate converts a request into an exposure candidate.
func buildCandidate(req candidateRequest) *exposureCandidate {
	return &exposureCandidate{
		priority: req.Priority,
		finding: ExposureClassification{
			ID:             req.ID,
			Bucket:         req.BucketName,
			ExposureType:   req.ExposureType,
			PrincipalScope: req.PrincipalScope,
			Actions:        req.Actions,
			WriteScope:     req.WriteScope,
			EvidencePath:   req.Evidence,
		},
	}
}

type readExposureInput struct {
	bucketName           string
	bucketWebsiteEnabled bool
	globalGet            bool
	writeAbsorbsRead     bool
	hasAuthenticatedOnly bool
	policyGet            bool
	aclGet               bool
	principalScope       kernel.PrincipalScope
	readEvidence         []string
	policyReadEvidence   []string
	aclReadEvidence      []string
}

func selectReadExposureCandidate(in readExposureInput) *exposureCandidate {
	if !in.globalGet || in.writeAbsorbsRead {
		return nil
	}

	var best *exposureCandidate

	if in.bucketWebsiteEnabled {
		evidence := in.aclReadEvidence
		if in.policyGet {
			evidence = in.readEvidence
		}
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityWebsitePublic,
			ID:             exposureIDWebsitePublic,
			ExposureType:   "website_public",
			Actions:        []string{outputGetObject},
			Evidence:       appendEvidence([]string{"bucket.website.enabled"}, evidence...),
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
		}))
	}

	if in.hasAuthenticatedOnly {
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityAuthOnly,
			ID:             exposureIDGlobalAuthenticatedRead,
			ExposureType:   "authenticated_read",
			Actions:        []string{outputGetObject},
			Evidence:       in.readEvidence,
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
		}))
	}

	if in.policyGet {
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityPolicyRead,
			ID:             exposureIDPublicRead,
			ExposureType:   "public_read",
			Actions:        []string{outputGetObject},
			Evidence:       in.policyReadEvidence,
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
		}))
	}

	if in.aclGet {
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityACLRead,
			ID:             exposureIDACLPublicRead,
			ExposureType:   "acl_public_read",
			Actions:        []string{outputGetObject},
			Evidence:       in.aclReadEvidence,
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
		}))
	}

	return best
}

type writeExposureInput struct {
	bucketName          string
	globalPut           bool
	policyPut           bool
	aclPut              bool
	principalScope      kernel.PrincipalScope
	writeScope          string
	policyWriteEvidence []string
	aclWriteEvidence    []string
	writeSourceHasGet   bool
	writeSourceHasList  bool
}

func selectWriteExposureCandidate(in writeExposureInput) *exposureCandidate {
	if !in.globalPut {
		return nil
	}

	var best *exposureCandidate

	if in.policyPut {
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityPolicyWrite,
			ID:             exposureIDPublicWrite,
			ExposureType:   "public_write",
			Actions:        writeActions(in.writeSourceHasGet, in.writeSourceHasList),
			Evidence:       in.policyWriteEvidence,
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
			WriteScope:     in.writeScope,
		}))
	}

	if in.aclPut {
		best = better(best, buildCandidate(candidateRequest{
			Priority:       priorityACLWrite,
			ID:             exposureIDACLPublicWrite,
			ExposureType:   "acl_public_write",
			Actions:        []string{outputPutObject},
			Evidence:       in.aclWriteEvidence,
			BucketName:     in.bucketName,
			PrincipalScope: in.principalScope,
			WriteScope:     in.writeScope,
		}))
	}

	return best
}

func better(current, next *exposureCandidate) *exposureCandidate {
	if current == nil || next.priority > current.priority {
		return next
	}
	return current
}

func writeActions(hasGet, hasList bool) []string {
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

func appendEvidence(prefix []string, base ...string) []string {
	result := make([]string, 0, len(prefix)+len(base))
	result = append(result, prefix...)
	result = append(result, base...)
	return result
}
