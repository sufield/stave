package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eks_pod_spec — 11 controls. No single .kind discriminator; the
// controls read narrower paths under k8s.pod_spec.*. The host-namespace
// and privilege flags are the foundational containment-break signals;
// is_infrastructure_daemonset is the near-universal exemption guard.
var eksPodSpecSchema = Schema{
	AssetType: kernel.AssetType("aws_eks_pod_spec"),
	Fields: []FieldRequirement{
		{Path: "properties.k8s.pod_spec.is_infrastructure_daemonset", Required: true,
			Doc: "infra-DaemonSet guard; host-access controls exempt on this"},
		{Path: "properties.k8s.pod_spec.has_host_network", Required: true,
			Doc: "hostNetwork containment-break signal"},
		{Path: "properties.k8s.pod_spec.has_host_pid", Required: true,
			Doc: "hostPID containment-break signal"},
		{Path: "properties.k8s.pod_spec.has_host_ipc", Required: true,
			Doc: "hostIPC containment-break signal"},
		{Path: "properties.k8s.pod_spec.has_privileged_container", Required: true,
			Doc: "privileged-container detection signal"},
		{Path: "properties.k8s.pod_spec.allow_privilege_escalation", Required: false,
			Doc: "privilege-escalation flag; sparse when securityContext unset"},
		{Path: "properties.k8s.pod_spec.has_ghost_configmap_ref", Required: false,
			Doc: "ghost ConfigMap ref; sparse, only when a ref is dangling"},
		{Path: "properties.k8s.pod_spec.has_ghost_secret_ref", Required: false,
			Doc: "ghost Secret ref; sparse, only when a ref is dangling"},
	},
}

func init() { Register(eksPodSpecSchema) }
