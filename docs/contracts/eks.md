# Observation Contract: Amazon EKS

## Asset Type

```
vendor: "aws"
type: "eks_cluster" (uses properties.k8s.kind = "cluster")
```

Scope tags: `aws`, `eks`, `k8s`

## Properties Schema

### k8s (cluster-level)

| Property | Type | Description |
|---|---|---|
| `k8s.kind` | string | Always "cluster" for EKS cluster assets |
| `k8s.cluster.version` | string | Kubernetes version (e.g. "1.33") |
| `k8s.cluster.version_deprecated` | bool | Version has reached end-of-support |

### addons

| Property | Type | Description |
|---|---|---|
| `addons.vpc_cni.version` | string | VPC CNI addon version |
| `addons.vpc_cni.enable_network_policy` | bool | NetworkPolicy enforcement enabled |
| `addons.vpc_cni.enable_pod_eni` | bool | Pod-level ENI assignment |
| `addons.vpc_cni.pod_completion_firewall_flush` | bool | Firewall rules flushed on pod completion |

### feature_gates

| Property | Type | Description |
|---|---|---|
| `feature_gates.ttl_after_finished_controller` | bool | TTLAfterFinished controller enabled |

### jobs (flat booleans)

| Property | Type | Description |
|---|---|---|
| `jobs.has_job_without_ttl_in_netpol_ns` | bool | Job without TTL in a NetworkPolicy namespace |

## Sample Extractor

An EKS extractor queries the cluster via AWS API + kubectl:
- Cluster version: `aws eks describe-cluster`
- VPC CNI addon: `aws eks describe-addon --addon-name vpc-cni`
- Feature gates: `kubectl get nodes -o json`
- Jobs: `kubectl get jobs -A -o json`
- NetworkPolicy: `kubectl get networkpolicy -A`

Output: obs.v0.1 JSON with `vendor: "aws"`, `properties.k8s.kind: "cluster"`.
