package exposure

import (
	"fmt"
	"sort"

	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	// Output action labels (used by resolve logic for non-selection findings).
	outputListBucket   = "s3:ListBucket"
	outputGetBucketACL = "s3:GetBucketAcl"
	outputPutBucketACL = "s3:PutBucketAcl"
	outputDeleteObject = "s3:DeleteObject"

	// Canonical exposure classification IDs.
	idResourceTakeover    kernel.ControlID = "CTL.S3.BUCKET.TAKEOVER.001"
	idWebPublic           kernel.ControlID = "CTL.S3.WEBSITE.PUBLIC.001"
	idAuthenticatedRead   kernel.ControlID = "CTL.S3.GLOBAL.AUTHENTICATED.READ.001"
	idPublicRead          kernel.ControlID = "CTL.S3.PUBLIC.READ.001"
	idResourcePublicRead  kernel.ControlID = "CTL.S3.ACL.PUBLIC.READ.001"
	idPublicList          kernel.ControlID = "CTL.S3.PUBLIC.LIST.001"
	idPublicWrite         kernel.ControlID = "CTL.S3.PUBLIC.WRITE.001"
	idResourcePublicWrite kernel.ControlID = "CTL.S3.ACL.PUBLIC.WRITE.001"
	idPublicAdminRead     kernel.ControlID = "CTL.S3.PUBLIC.ACL.READ.001"
	idPublicAdminWrite    kernel.ControlID = "CTL.S3.PUBLIC.ACL.WRITE.001"
	idPublicDelete        kernel.ControlID = "CTL.S3.PUBLIC.DELETE.001"
)

func init() {
	validateExposureControlIDs()
}

func validateExposureControlIDs() {
	for _, id := range []kernel.ControlID{
		idResourceTakeover,
		idWebPublic,
		idAuthenticatedRead,
		idPublicRead,
		idResourcePublicRead,
		idPublicList,
		idPublicWrite,
		idResourcePublicWrite,
		idPublicAdminRead,
		idPublicAdminWrite,
		idPublicDelete,
	} {
		if err := kernel.ValidateControlIDFormat(id.String()); err != nil {
			panic(fmt.Sprintf("invalid exposure control ID %q: %v", id, err))
		}
	}
}

// ClassifyExposure processes normalized bucket inputs and returns merged,
// deduplicated exposure classifications.
func ClassifyExposure(buckets []NormalizedBucketInput) []ExposureClassification {
	var findings []ExposureClassification

	for _, b := range buckets {
		findings = append(findings, classifyBucket(b)...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Resource != findings[j].Resource {
			return findings[i].Resource < findings[j].Resource
		}
		return findings[i].ID < findings[j].ID
	})

	return findings
}

func classifyBucket(b NormalizedBucketInput) []ExposureClassification {
	if !b.Exists && b.ExternalReference {
		return []ExposureClassification{{
			ID:             idResourceTakeover,
			Resource:       b.Name,
			ExposureType:   "bucket_takeover",
			PrincipalScope: kernel.ScopeNotApplicable,
			Actions:        []string{},
			EvidencePath:   []string{"bucket.exists", "bucket.external_reference"},
		}}
	}

	ctx := bucketResolutionContext{input: b}

	var findings []ExposureClassification
	findings = append(findings, ctx.resolveRead()...)
	findings = append(findings, ctx.resolveList()...)
	findings = append(findings, ctx.resolveWrite()...)
	findings = append(findings, ctx.resolveManagement()...)
	return findings
}
