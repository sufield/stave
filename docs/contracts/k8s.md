# Kubernetes Observation Contract

Observation schema for Kubernetes cluster components. Each observation
captures the configuration state of a single component instance
(API server, etcd, kubelet, controller manager, scheduler).

## Asset Types

| Type | Description |
|------|-------------|
| `k8s_apiserver` | API server configuration |
| `k8s_etcd` | etcd datastore configuration |
| `k8s_kubelet` | Kubelet node agent configuration |
| `k8s_controller_manager` | Controller manager configuration |
| `k8s_scheduler` | Scheduler configuration |
| `k8s_cluster` | Cluster-level configuration (audit, secrets, RBAC) |

Vendor: `kubernetes`

## Property Paths

### apiserver

```yaml
properties:
  apiserver:
    anonymous_auth_enabled: bool      # --anonymous-auth flag
    audit_log_enabled: bool           # --audit-log-path is set
    audit_log_maxage: int             # --audit-log-maxage value (days)
    authorization_mode: string        # --authorization-mode (e.g. "RBAC,Node")
    tls_cert_file: string             # --tls-cert-file path
    client_ca_file: string            # --client-ca-file path
    etcd_certfile: string             # --etcd-certfile path
    token_auth_file: string           # --token-auth-file path (empty = good)
    service_account_key_file: string  # --service-account-key-file path
```

### etcd

```yaml
properties:
  etcd:
    cert_file: string          # --cert-file path
    key_file: string           # --key-file path
    client_cert_auth: bool     # --client-cert-auth flag
    auto_tls: bool             # --auto-tls flag (should be false)
    peer_auto_tls: bool        # --peer-auto-tls flag (should be false)
```

### kubelet

```yaml
properties:
  kubelet:
    anonymous_auth_enabled: bool     # authentication.anonymous.enabled
    authorization_mode: string       # authorization.mode
    client_ca_file: string           # authentication.x509.clientCAFile
    read_only_port: int              # readOnlyPort (0 = disabled)
    protect_kernel_defaults: bool    # protectKernelDefaults
    tls_cert_file: string            # tlsCertFile
    rotate_certificates: bool        # rotateCertificates
```

### controller_manager

```yaml
properties:
  controller_manager:
    use_service_account_credentials: bool      # --use-service-account-credentials
    service_account_private_key_file: string   # --service-account-private-key-file
    terminated_pod_gc_threshold: int           # --terminated-pod-gc-threshold
```

### scheduler

```yaml
properties:
  scheduler:
    profiling_enabled: bool    # --profiling flag
```

### Cluster-level (existing)

```yaml
properties:
  audit:
    kind: string                  # "cluster"
    audit_logging_enabled: bool
  secrets:
    kind: string                  # "cluster"
    etcd_encryption_enabled: bool
  rbac:
    kind: string                  # "cluster_role"
    has_wildcard_resources: bool
    has_wildcard_verbs: bool
  network:
    kind: string                  # "namespace"
    has_network_policy: bool
    has_default_deny_ingress: bool
  auth:
    kind: string                  # "cluster"
    has_aws_iam_authenticator: bool
    aws_access_key_mapping: bool

  # IMDS protection
  network_policies:
    blocks_imds_egress: bool        # NetworkPolicy blocking 169.254.169.254/32 egress

  # Job workload lifecycle (flat booleans for predicate evaluation)
  jobs:
    has_job_without_ttl_in_netpol_ns: bool  # Job with no TTL in a NetworkPolicy namespace

  controllers:
    ttl_after_finished_enabled: bool        # TTLAfterFinished controller active
```
