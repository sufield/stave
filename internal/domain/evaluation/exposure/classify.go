package exposure

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	// Output action labels.
	outputGetObject    = "s3:GetObject"
	outputPutObject    = "s3:PutObject"
	outputListBucket   = "s3:ListBucket"
	outputGetBucketACL = "s3:GetBucketAcl"
	outputPutBucketACL = "s3:PutBucketAcl"
	outputDeleteObject = "s3:DeleteObject"

	// Canonical exposure classification IDs.
	exposureIDBucketTakeover          kernel.ControlID = "CTL.S3.BUCKET.TAKEOVER.001"
	exposureIDWebsitePublic           kernel.ControlID = "CTL.S3.WEBSITE.PUBLIC.001"
	exposureIDGlobalAuthenticatedRead kernel.ControlID = "CTL.S3.GLOBAL.AUTHENTICATED.READ.001"
	exposureIDPublicRead              kernel.ControlID = "CTL.S3.PUBLIC.READ.001"
	exposureIDACLPublicRead           kernel.ControlID = "CTL.S3.ACL.PUBLIC.READ.001"
	exposureIDPublicList              kernel.ControlID = "CTL.S3.PUBLIC.LIST.001"
	exposureIDPublicWrite             kernel.ControlID = "CTL.S3.PUBLIC.WRITE.001"
	exposureIDACLPublicWrite          kernel.ControlID = "CTL.S3.ACL.PUBLIC.WRITE.001"
	exposureIDPublicACLRead           kernel.ControlID = "CTL.S3.PUBLIC.ACL.READ.001"
	exposureIDPublicACLWrite          kernel.ControlID = "CTL.S3.PUBLIC.ACL.WRITE.001"
	exposureIDPublicDelete            kernel.ControlID = "CTL.S3.PUBLIC.DELETE.001"
)

func init() {
	validateExposureControlIDs()
}

func validateExposureControlIDs() {
	for _, id := range []kernel.ControlID{
		exposureIDBucketTakeover,
		exposureIDWebsitePublic,
		exposureIDGlobalAuthenticatedRead,
		exposureIDPublicRead,
		exposureIDACLPublicRead,
		exposureIDPublicList,
		exposureIDPublicWrite,
		exposureIDACLPublicWrite,
		exposureIDPublicACLRead,
		exposureIDPublicACLWrite,
		exposureIDPublicDelete,
	} {
		if err := kernel.ValidateControlIDFormat(id.String()); err != nil {
			panic(fmt.Sprintf("invalid exposure control ID %q: %v", id, err))
		}
	}
}

// ClassifyExposure processes a list of buckets and returns merged, deduplicated
// exposure classifications.
func ClassifyExposure(buckets []ExposureBucketInput) []ExposureClassification {
	var findings []ExposureClassification

	for _, b := range buckets {
		findings = append(findings, classifyBucket(b)...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Bucket != findings[j].Bucket {
			return findings[i].Bucket < findings[j].Bucket
		}
		return findings[i].ID < findings[j].ID
	})

	return findings
}

func classifyBucket(b ExposureBucketInput) []ExposureClassification {
	if !b.Exists && b.ExternalReference {
		return []ExposureClassification{{
			ID:             exposureIDBucketTakeover,
			Bucket:         b.Name,
			ExposureType:   "bucket_takeover",
			PrincipalScope: kernel.ScopeNotApplicable,
			Actions:        []string{},
			EvidencePath:   []string{"bucket.exists", "bucket.external_reference"},
		}}
	}

	ctx := newBucketResolutionContext(b)

	var findings []ExposureClassification
	findings = append(findings, ctx.resolveRead()...)
	findings = append(findings, ctx.resolveList()...)
	findings = append(findings, ctx.resolveWrite()...)
	findings = append(findings, ctx.resolveManagement()...)
	return findings
}

// classifyPrincipal returns (isGlobal, isAuthenticated) for a policy principal string.
func classifyPrincipal(principal string) (bool, bool) {
	p := strings.TrimSpace(principal)
	if p == policyWildcard {
		return true, false
	}
	if isAuthenticatedUsersPrincipalToken(p) {
		return false, true
	}
	return false, false
}
