package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eks_namespace — 12 controls. Like aws_eks_cluster there is no
// single .kind discriminator; controls read narrower paths under
// k8s.namespace.*. is_system_namespace is the near-universal guard
// (controls exempt system namespaces), and the quota/network/tenancy
// counts are the foundational detection signals.
var eksNamespaceSchema = Schema{
	AssetType: kernel.AssetType("aws_eks_namespace"),
	Fields: []FieldRequirement{
		{Path: "properties.k8s.namespace.is_system_namespace", Required: true,
			Doc: "system-namespace guard; nearly every namespace control exempts on this"},
		{Path: "properties.k8s.namespace.tenant_count", Required: true,
			Doc: "multi-tenancy detection signal"},
		{Path: "properties.k8s.namespace.resource_quota_count", Required: true,
			Doc: "ResourceQuota presence — capacity-exhaustion gate"},
		{Path: "properties.k8s.namespace.has_default_deny_ingress", Required: true,
			Doc: "default-deny ingress NetworkPolicy signal"},
		{Path: "properties.k8s.namespace.has_default_deny_egress", Required: true,
			Doc: "default-deny egress NetworkPolicy signal"},
		{Path: "properties.k8s.namespace.has_psa_enforce_label", Required: false,
			Doc: "Pod Security Admission enforce label; sparse when PSA unset"},
		{Path: "properties.k8s.namespace.has_cost_allocation_label", Required: false,
			Doc: "cost-allocation label; sparse compliance/chargeback signal"},
	},
}

func init() { Register(eksNamespaceSchema) }
