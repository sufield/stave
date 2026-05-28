package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eks_cluster — 19 controls. Unlike most asset types, EKS does
// NOT have a single high-fanout .kind discriminator; the controls
// each read narrower property paths under k8s.cluster.*. The
// schema reflects that — Required is reserved for the handful of
// paths that map to high-severity controls.
var eksClusterSchema = Schema{
	AssetType: kernel.AssetType("aws_eks_cluster"),
	Fields: []FieldRequirement{
		{Path: "properties.k8s.cluster.is_dr_cluster", Required: false,
			Doc: "DR-class hint for capacity controls"},
		{Path: "properties.k8s.cluster.image_signature_verification_enabled", Required: false,
			Doc: "image-signing audit; sparse when not configured"},
		{Path: "properties.k8s.cluster.oidc_url_unique_in_account", Required: false,
			Doc: "OIDC-uniqueness signal for IRSA controls"},
		{Path: "properties.k8s.cluster.shared_via_ram", Required: false,
			Doc: "RAM-sharing signal; sparse for non-shared clusters"},
		{Path: "properties.k8s.cluster.ram_principal_org_id_set", Required: false,
			Doc: "RAM-org-scope signal; depends on shared_via_ram"},
	},
}

func init() { Register(eksClusterSchema) }
