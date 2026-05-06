package iam

import (
	"github.com/sufield/stave/internal/core/asset"
)

// ResourceRoleBinding records that an AWS service resource (a
// Lambda function, a CloudFormation stack, an ECS task definition,
// etc.) has a specific IAM role attached. Iter 6 (confused deputy)
// uses these bindings to detect the *use-existing* privesc
// pattern: an attacker with a trigger action on the resource gains
// the role's permissions WITHOUT needing iam:PassRole, because the
// binding was established before the attack.
//
// Iter 3's create-and-pass walker requires PassRole + a trigger
// action on a service principal. Iter 6's invoke-existing walker
// requires only the trigger action on a specific resource ARN
// whose binding is already in the snapshot. Both walkers can fire
// on the same chain when applicable; they describe distinct attack
// paths with distinct prerequisites.
type ResourceRoleBinding struct {
	// ResourceARN of the bound service resource (e.g., a Lambda
	// function ARN or a CloudFormation stack ARN).
	ResourceARN string

	// RoleARN attached to the resource. Must match an entry in the
	// snapshot's identity index for the walker to emit a chain
	// (we never invent privilege levels for roles we cannot resolve).
	RoleARN string

	// ServiceKind names the AWS service the resource belongs to,
	// drawn from a small canonical set ("lambda", "cloudformation",
	// etc.). Used to select the matching trigger-action set when
	// the walker decides whether a given principal-grant tuple
	// activates the binding.
	ServiceKind string
}

// ExtractResourceRoleBindings scans every Asset in the snapshot
// and returns a map keyed by resource ARN holding the AWS
// service-role binding (when present).
//
// Iter 6 v1 covers:
//   - aws_lambda_function:        properties.compute.role_arn
//   - aws_cloudformation_stack:   properties.cloudformation.role_arn
//
// Other services (ECS task definitions, CodeBuild projects, Glue
// jobs) follow the same pattern and can be added by extending the
// resourceBindingExtractors table — kept narrow in v1 so the
// initial detection set is exhaustive on its slice rather than
// shallow across many. The extractor SILENTLY skips assets without
// a recognised role property: an unrelated bucket or VPC has no
// binding to record, which is correct.
func ExtractResourceRoleBindings(snap *asset.Snapshot) map[string]ResourceRoleBinding {
	if snap == nil {
		return nil
	}
	out := make(map[string]ResourceRoleBinding, len(snap.Assets))
	for i := range snap.Assets {
		a := &snap.Assets[i]
		extractor, ok := resourceBindingExtractors[string(a.Type)]
		if !ok {
			continue
		}
		roleARN := readRolePropertyByPath(a.Properties, extractor.RolePath)
		if roleARN == "" {
			continue
		}
		out[string(a.ID)] = ResourceRoleBinding{
			ResourceARN: string(a.ID),
			RoleARN:     roleARN,
			ServiceKind: extractor.ServiceKind,
		}
	}
	return out
}

// resourceBindingExtractor describes how to read the role-ARN
// binding off one asset type's Properties tree. Each entry pairs
// the service-kind label the walker uses to pick a trigger-action
// set with the canonical property path stave's collectors emit.
type resourceBindingExtractor struct {
	ServiceKind string
	RolePath    []string
}

// resourceBindingExtractors is the v1 lookup table. Adding a new
// service is a single-line extension of this map; the walker
// machinery is data-driven and needs no edits per service.
//
// Property paths reflect the existing Stave convention scattered
// across the embedded controls: Lambda functions live under
// properties.compute.role_arn (consistent with stepfunctions/
// CTL.STEPFUNCTIONS.LAMBDA.ROLE.DRIFT.001), CloudFormation under
// properties.cloudformation.role_arn. New entries should follow
// the same `properties.<service>.role_arn` shape so collectors
// can populate them without bespoke schema updates.
var resourceBindingExtractors = map[string]resourceBindingExtractor{
	"aws_lambda_function": {
		ServiceKind: "lambda",
		RolePath:    []string{"compute", "role_arn"},
	},
	"aws_cloudformation_stack": {
		ServiceKind: "cloudformation",
		RolePath:    []string{"cloudformation", "role_arn"},
	},
}

// readRolePropertyByPath walks the supplied property path against
// asset properties and returns the leaf string. Returns "" when
// any segment is missing or non-map, matching the soft-extraction
// contract every Stave collector path uses.
func readRolePropertyByPath(props map[string]any, path []string) string {
	v, ok := walkProperty(props, path)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
