package schema

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// TestCoverage_HighVolumeAssetTypesRegistered enumerates the
// asset types this package commits to covering and asserts each
// has a non-empty schema registered. New schema files must add
// their asset type to expectedTypes — that fixed list IS the
// coverage contract.
//
// When the catalog grows a new high-volume asset type, the
// process is:
//  1. Add a `properties.X.kind`-style schema file in this package
//     and Register() it in an init().
//  2. Add the asset-type string to expectedTypes below.
//  3. The TestCoverage check enforces the pair stays in sync.
func TestCoverage_HighVolumeAssetTypesRegistered(t *testing.T) {
	expectedTypes := []kernel.AssetType{
		"aws_s3_bucket",
		"aws_stepfunctions_state_machine",
		"aws_opensearch_domain",
		"aws_cognito_user_pool",
		"aws_lambda_function",
		"aws_cloudtrail_trail",
		"aws_kms_key",
		"aws_ec2_instance",
		"aws_sqs_queue",
		"aws_iam_user",
		"aws_iam_role",
		"aws_sns_topic",
		"aws_eks_cluster",
		"aws_ec2_security_group",
		"aws_eventbridge_bus",
	}
	for _, tt := range expectedTypes {
		t.Run(string(tt), func(t *testing.T) {
			s, ok := Lookup(tt)
			if !ok {
				t.Fatalf("no schema registered for %s", tt)
			}
			if len(s.Fields) == 0 {
				t.Errorf("schema for %s has no fields", tt)
			}
			// Every field declaration must carry a Doc string —
			// the field map is the contract between schema authors
			// and extractor maintainers; an empty Doc would make
			// the warning unactionable.
			for _, f := range s.Fields {
				if strings.TrimSpace(f.Doc) == "" {
					t.Errorf("%s: field %q has empty Doc", tt, f.Path)
				}
				if !strings.HasPrefix(f.Path, "properties.") {
					t.Errorf("%s: field %q does not start with 'properties.'", tt, f.Path)
				}
			}
		})
	}
}

// TestCoverage_EveryRegisteredSchemaHasARequiredField asserts the
// foundational invariant: a schema with NO Required fields
// produces no warnings even when the extractor is completely
// broken. The warning is the value, so the schema is worthless
// without at least one Required entry — unless the asset type
// genuinely has no anchor field (which the EKS schema documents
// inline). Allow-list those exceptions explicitly so the check
// stays meaningful for the rest.
func TestCoverage_EveryRegisteredSchemaHasARequiredField(t *testing.T) {
	allowedWithoutRequired := map[kernel.AssetType]bool{
		// EKS controls don't share a single .kind anchor — the
		// controls each gate on narrower paths. Documented inline
		// in eks_cluster.go.
		"aws_eks_cluster": true,
	}
	for typ, s := range Schemas {
		if allowedWithoutRequired[typ] {
			continue
		}
		hasRequired := false
		for _, f := range s.Fields {
			if f.Required {
				hasRequired = true
				break
			}
		}
		if !hasRequired {
			t.Errorf("schema for %s has zero Required fields — no extractor-regression visibility", typ)
		}
	}
}
