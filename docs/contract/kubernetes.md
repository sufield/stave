# Kubernetes Domain

Contract fields for Kubernetes cluster, namespace, and workload
observations. Namespace prefixes: `rbac.*`, `network_policy.*`, `secrets.*`,
`audit.*`.

Part of the [observation contract](README.md).

## Kubernetes Domain

### ClusterRole (`k8s_cluster_role`)

| Field | Type | Description |
|-------|------|-------------|
| `rbac.kind` | string | `"cluster_role"` — discriminator |
| `rbac.has_wildcard_resources` | bool | Rules include `resources: ["*"]` |
| `rbac.has_wildcard_verbs` | bool | Rules include `verbs: ["*"]` |

### Service Account (`k8s_service_account`)

| Field | Type | Description |
|-------|------|-------------|
| `rbac.kind` | string | `"service_account"` — discriminator |
| `rbac.is_default` | bool | Is the namespace default service account |
| `rbac.default_token_automount` | bool | automountServiceAccountToken enabled |

### Namespace (`k8s_namespace`)

| Field | Type | Description |
|-------|------|-------------|
| `network_policy.kind` | string | `"namespace"` — discriminator |
| `network_policy.has_network_policies` | bool | At least one NetworkPolicy exists |
| `network_policy.has_default_deny` | bool | Default-deny ingress policy exists |

### Cluster (`k8s_cluster`)

| Field | Type | Description |
|-------|------|-------------|
| `secrets.kind` | string | `"cluster"` — discriminator |
| `secrets.etcd_encryption_enabled` | bool | Secrets encrypted at rest in etcd |
| `audit.kind` | string | `"cluster"` — discriminator |
| `audit.audit_logging_enabled` | bool | API server audit logging enabled |

### Pod (`k8s_pod`)

| Field | Type | Description |
|-------|------|-------------|
| `secrets.kind` | string | `"pod"` — discriminator |
| `secrets.has_env_secrets` | bool | Secrets mounted as environment variables |

---

