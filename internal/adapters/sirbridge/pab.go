package sirbridge

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/compliance"
)

// extractPublicAccessBlock returns the bucket-level and
// account-level Public Access Block facts for a bucket asset.
// Each layer becomes a separate sir.PublicAccessBlockFact —
// AWS evaluation semantics are "either layer can suppress",
// which is a logical OR the L6 solver composes. Stave NEVER
// merges them in Go.
//
// Returns:
//   - empty slice when neither layer is present.
//   - one fact when only one layer is configured.
//   - two facts (bucket-level first, then account-level) when
//     both layers are configured.
//
// Source paths:
//   - bucket-level: ["PublicAccessBlockConfiguration"]
//   - account-level: ["AccountPublicAccessBlock"]
//
// Iter L3 contract: zero logical reasoning. The four PAB flags
// flow through verbatim. The extractor does NOT compute
// "is this bucket effectively blocked" — that's solver work.
func extractPublicAccessBlock(a asset.Asset) []sir.PublicAccessBlockFact {
	props := compliance.ParseS3Properties(a)

	var facts []sir.PublicAccessBlockFact
	if props.Controls.PublicAccessBlock.Present {
		facts = append(facts, sir.PublicAccessBlockFact{
			BlockPublicAcls:       props.Controls.PublicAccessBlock.BlockPublicACLs,
			IgnorePublicAcls:      props.Controls.PublicAccessBlock.IgnorePublicACLs,
			BlockPublicPolicy:     props.Controls.PublicAccessBlock.BlockPublicPolicy,
			RestrictPublicBuckets: props.Controls.PublicAccessBlock.RestrictPublicBuckets,
			Source: sir.SourceRef{
				Kind: "s3_public_access_block",
				ID:   string(a.ID),
				Path: []string{"PublicAccessBlockConfiguration"},
			},
		})
	}
	// Account-level PAB: the asset model exposes
	// AccountPublicAccessFullyBlocked as a single rolled-up
	// boolean rather than the four individual flags. AWS's
	// account-level PAB applies all four uniformly when set,
	// so map a single-flag-fully-blocked asset state to
	// "all four flags true". When the rolled-up flag is
	// false, the account-level PAB might still be partially
	// configured — the asset model doesn't surface that yet,
	// so we emit nothing rather than fabricate inputs.
	if props.Controls.AccountPublicAccessFullyBlocked {
		facts = append(facts, sir.PublicAccessBlockFact{
			BlockPublicAcls:       true,
			IgnorePublicAcls:      true,
			BlockPublicPolicy:     true,
			RestrictPublicBuckets: true,
			Source: sir.SourceRef{
				Kind: "s3_account_public_access_block",
				ID:   string(a.ID),
				Path: []string{"AccountPublicAccessBlock"},
			},
		})
	}
	return facts
}
