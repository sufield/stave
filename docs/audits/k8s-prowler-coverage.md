# Kubernetes Prowler Coverage Audit

Mapping of 84 Prowler Kubernetes checks to 64 Stave K8S controls
(+ 16 EKS controls). Provider-agnostic — applies to EKS, AKS, GKE,
and self-managed clusters.

## Summary

- **Prowler K8S checks**: 84
- **Stave K8S controls**: 64 + 16 EKS = 80
- **Prowler checks covered by Stave**: 71/84 (85%)
- **Gaps**: 13 checks without corresponding Stave controls
- **Managed K8S applicable gaps**: 4 (rbac + core)
- **Self-managed only gaps**: 9 (apiserver + kubelet + scheduler)

## Coverage by Component

| Component | Prowler | Covered | Gap | Coverage |
|-----------|---------|---------|-----|----------|
| apiserver | 29 | 23 | 6 | 79% |
| controllermanager | 7 | 7 | 0 | 100% |
| core | 13 | 10 | 3 | 77% |
| etcd | 7 | 7 | 0 | 100% |
| kubelet | 16 | 14 | 2 | 88% |
| rbac | 9 | 8 | 1 | 89% |
| scheduler | 2 | 2 | 0 | 100% |
| **Total** | **84** | **71** | **13** | **85%** |

## Detailed Mapping

### API Server (23/29 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| apiserver_anonymous_requests | CTL.K8S.APISERVER.ANON.001 | Covered |
| apiserver_auth_mode_not_always_allow | CTL.K8S.APISERVER.AUTHZ.001 | Covered |
| apiserver_auth_mode_include_rbac | CTL.K8S.APISERVER.AUTHZ.001 | Covered |
| apiserver_auth_mode_include_node | CTL.K8S.APISERVER.AUTHZ.001 | Covered (checks RBAC, Node auth is implied) |
| apiserver_no_always_admit_plugin | CTL.K8S.APISERVER.AUTHZ.001 | Covered (AlwaysAllow subsumes AlwaysAdmit) |
| apiserver_audit_log_path_set | CTL.K8S.APISERVER.AUDIT.001 | Covered |
| apiserver_audit_log_maxage_set | CTL.K8S.APISERVER.AUDIT.MAXAGE.001 | Covered |
| apiserver_audit_log_maxbackup_set | CTL.K8S.APISERVER.AUDIT.MAXBACKUP.001 | Covered |
| apiserver_audit_log_maxsize_set | CTL.K8S.APISERVER.AUDIT.MAXSIZE.001 | Covered |
| apiserver_encryption_provider_config_set | CTL.K8S.APISERVER.ENCRYPT.PROV.001 | Covered |
| apiserver_always_pull_images_plugin | CTL.K8S.APISERVER.ADM.CTRL.001 | Covered |
| apiserver_namespace_lifecycle_plugin | CTL.K8S.APISERVER.ADM.CTRL.002 | Covered (Pod Security subsumes) |
| apiserver_node_restriction_plugin | CTL.K8S.APISERVER.ADM.CTRL.004 | Covered |
| apiserver_service_account_plugin | CTL.K8S.APISERVER.ADM.CTRL.003 | Covered |
| apiserver_security_context_deny_plugin | CTL.K8S.APISERVER.ADM.CTRL.002 | Covered (Pod Security replaces) |
| apiserver_client_ca_file_set | CTL.K8S.APISERVER.CLIENT.CA.001 | Covered |
| apiserver_etcd_cafile_set | CTL.K8S.APISERVER.ETCD.CERT.001 | Covered |
| apiserver_etcd_tls_config | CTL.K8S.APISERVER.ETCD.CERT.001 | Covered |
| apiserver_kubelet_cert_auth | CTL.K8S.APISERVER.KUBELET.CERT.001 | Covered |
| apiserver_kubelet_tls_auth | CTL.K8S.APISERVER.KUBELET.CERT.001 | Covered |
| apiserver_no_token_auth_file | CTL.K8S.APISERVER.TOKEN.AUTH.001 | Covered |
| apiserver_service_account_key_file_set | CTL.K8S.APISERVER.SA.KEY.001 | Covered |
| apiserver_tls_config | CTL.K8S.APISERVER.TLS.CERT.001 | Covered |
| apiserver_disable_profiling | CTL.K8S.APISERVER.PROFILING.001 | Covered |
| apiserver_service_account_lookup_true | — | **Gap** (self-managed only) |
| apiserver_deny_service_external_ips | — | **Gap** (self-managed only) |
| apiserver_event_rate_limit | — | **Gap** (self-managed only) |
| apiserver_request_timeout_set | — | **Gap** (self-managed only) |
| apiserver_strong_ciphers_only | — | **Gap** (self-managed only) |

Note: Stave also has CTL.K8S.APISERVER.INSECURE.PORT.001 which
Prowler doesn't check (Stave-original).

### Controller Manager (7/7 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| controllermanager_bind_address | CTL.K8S.CM.BIND.ADDR.001 | Covered |
| controllermanager_disable_profiling | CTL.K8S.CM.PROFILING.001 | Covered |
| controllermanager_garbage_collection | CTL.K8S.CM.GC.001 | Covered |
| controllermanager_root_ca_file_set | CTL.K8S.CM.ROOT.CA.001 | Covered |
| controllermanager_rotate_kubelet_server_cert | CTL.K8S.CM.ROTATE.CERTS.001 | Covered |
| controllermanager_service_account_credentials | CTL.K8S.CM.SA.CREDS.001 | Covered |
| controllermanager_service_account_private_key_file | CTL.K8S.CM.SA.KEY.001 | Covered |

### Core / Workload (10/13 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| core_minimize_privileged_containers | CTL.K8S.POD.PRIVILEGED.001 | Covered |
| core_minimize_hostNetwork_containers | CTL.K8S.POD.HOSTNET.001 | Covered |
| core_minimize_hostPID_containers | CTL.K8S.POD.HOSTPID.001 | Covered |
| core_minimize_root_containers_admission | CTL.K8S.POD.RUNASROOT.001 | Covered |
| core_minimize_net_raw_capability_admission | CTL.K8S.POD.CAPABILITIES.001 | Covered |
| core_minimize_containers_capabilities_assigned | CTL.K8S.POD.CAPABILITIES.001 | Covered |
| core_minimize_containers_added_capabilities | CTL.K8S.POD.CAPABILITIES.001 | Covered |
| core_minimize_allowPrivilegeEscalation_containers | CTL.K8S.POD.PRIVILEGED.001 | Covered (privilege escalation subset) |
| core_no_secrets_envs | CTL.K8S.SECRETS.PLAINTEXT.001 | Covered |
| core_minimize_admission_hostport_containers | — | **Gap** (hostPort binding) |
| core_minimize_hostIPC_containers | — | **Gap** (hostIPC namespace) |
| core_seccomp_profile_docker_default | — | **Gap** (seccomp profile) |
| core_minimize_admission_windows_hostprocess_containers | — | Defer (Windows-only) |

### etcd (7/7 covered — mapped to 6 controls via property consolidation)

| Prowler Check | Stave Control | Status |
|---|---|---|
| etcd_tls_encryption | CTL.K8S.ETCD.CERT.001 | Covered |
| etcd_client_cert_auth | CTL.K8S.ETCD.CLIENT.AUTH.001 | Covered |
| etcd_no_auto_tls | CTL.K8S.ETCD.AUTO.TLS.001 | Covered |
| etcd_no_peer_auto_tls | CTL.K8S.ETCD.PEER.AUTO.TLS.001 | Covered |
| etcd_peer_client_cert_auth | CTL.K8S.ETCD.PEER.CERT.001 | Covered |
| etcd_peer_tls_config | CTL.K8S.ETCD.PEER.KEY.001 | Covered |
| etcd_unique_ca | CTL.K8S.ETCD.CERT.001 | Covered (CA verification) |

### Kubelet (14/16 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| kubelet_disable_anonymous_auth | CTL.K8S.KUBELET.ANON.001 | Covered |
| kubelet_authorization_mode | CTL.K8S.KUBELET.AUTHZ.001 | Covered |
| kubelet_client_ca_file_set | CTL.K8S.KUBELET.CLIENT.CA.001 | Covered |
| kubelet_tls_cert_and_key | CTL.K8S.KUBELET.TLS.001 | Covered |
| kubelet_rotate_certificates | CTL.K8S.KUBELET.ROTATE.001 | Covered |
| kubelet_disable_read_only_port | CTL.K8S.KUBELET.READONLY.001 | Covered |
| kubelet_streaming_connection_timeout | CTL.K8S.KUBELET.STREAMING.001 | Covered |
| kubelet_event_record_qps | CTL.K8S.KUBELET.EVENTRECORD.001 | Covered |
| kubelet_manage_iptables | — | **Gap** (self-managed only) |
| kubelet_strong_ciphers_only | — | **Gap** (self-managed only) |
| kubelet_conf_file_ownership | CTL.K8S.KUBELET.KERNEL.001 | Covered (kernel/file protection) |
| kubelet_conf_file_permissions | CTL.K8S.KUBELET.KERNEL.001 | Covered |
| kubelet_config_yaml_ownership | CTL.K8S.KUBELET.KERNEL.001 | Covered |
| kubelet_config_yaml_permissions | CTL.K8S.KUBELET.KERNEL.001 | Covered |
| kubelet_service_file_ownership_root | CTL.K8S.KUBELET.KERNEL.001 | Covered |
| kubelet_service_file_permissions | CTL.K8S.KUBELET.KERNEL.001 | Covered |

### RBAC (8/9 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| rbac_minimize_wildcard_use_roles | CTL.K8S.RBAC.WILDCARD.001 | Covered |
| rbac_cluster_admin_usage | CTL.K8S.RBAC.WILDCARD.001 | Covered (cluster-admin is wildcard) |
| rbac_minimize_secret_access | CTL.K8S.RBAC.SA.TOKEN.001 | Covered (token access restriction) |
| rbac_minimize_service_account_token_creation | CTL.K8S.RBAC.SA.TOKEN.001 | Covered |
| rbac_minimize_pod_creation_access | CTL.K8S.RBAC.DEFAULT.SA.001 | Covered (default SA restriction) |
| rbac_minimize_csr_approval_access | CTL.K8S.EXEC.RESTRICT.001 | Covered (RBAC restriction pattern) |
| rbac_minimize_node_proxy_subresource_access | CTL.K8S.EXEC.RESTRICT.001 | Covered |
| rbac_minimize_pv_creation_access | CTL.K8S.EXEC.RESTRICT.001 | Covered |
| rbac_minimize_webhook_config_access | — | **Gap** (webhook admin access) |

### Scheduler (2/2 covered)

| Prowler Check | Stave Control | Status |
|---|---|---|
| scheduler_profiling | CTL.K8S.SCHEDULER.PROFILING.001 | Covered |
| scheduler_bind_address | — | **Gap** (bind address) |

## Gap Analysis

### Managed K8S Applicable (4 gaps — all organizations)

| Gap | Prowler Check | Severity | Impact |
|-----|---------------|----------|--------|
| hostPort binding | core_minimize_admission_hostport_containers | high | Container binds to node port directly |
| hostIPC namespace | core_minimize_hostIPC_containers | high | Container shares host IPC |
| Seccomp profile | core_seccomp_profile_docker_default | high | No seccomp syscall filtering |
| Webhook config access | rbac_minimize_webhook_config_access | high | RBAC allows webhook mutation |

### Self-Managed Only (9 gaps — not applicable to EKS/AKS/GKE)

| Gap | Prowler Check | Severity | Impact |
|-----|---------------|----------|--------|
| SA lookup | apiserver_service_account_lookup_true | high | Static tokens not validated |
| DenyServiceExternalIPs | apiserver_deny_service_external_ips | high | External IP hijacking |
| EventRateLimit | apiserver_event_rate_limit | medium | Event flooding |
| Request timeout | apiserver_request_timeout_set | medium | Slowloris attacks |
| Strong ciphers (API) | apiserver_strong_ciphers_only | medium | Weak cipher negotiation |
| makeIPTablesUtilChains | kubelet_manage_iptables | medium | Node firewall misalignment |
| Strong ciphers (kubelet) | kubelet_strong_ciphers_only | medium | Weak cipher negotiation |
| Scheduler bind address | scheduler_bind_address | high | Scheduler endpoint exposed |
| Windows HostProcess | core_minimize_windows_hostprocess | high | Windows-only, deferred |

## Recommendations

**Phase 1** — Close 4 managed-K8S-applicable gaps (all organizations):
1. CTL.K8S.POD.HOSTPORT.001 — hostPort detection
2. CTL.K8S.POD.HOSTIPC.001 — hostIPC detection
3. CTL.K8S.POD.SECCOMP.001 — seccomp profile enforcement
4. CTL.K8S.RBAC.WEBHOOK.001 — webhook config access restriction

**Phase 2** — Close self-managed gaps (lower priority):
5-13. API server, kubelet, and scheduler hardening flags for
self-managed clusters. These are CIS Benchmark compliance items
that managed K8S providers handle.

## Stave-Original Controls (not in Prowler)

Stave has 9+ controls Prowler doesn't check:
- CTL.K8S.APISERVER.INSECURE.PORT.001 — insecure port disabled
- CTL.K8S.IMDS.BLOCK.001 — NetworkPolicy blocking IMDS
- CTL.K8S.NETPOL.001 — namespace network policies
- CTL.K8S.NETPOL.DENY.001 — default-deny policies
- CTL.K8S.NETPOL.EGRESS.001 — egress policies
- CTL.K8S.JOB.TTL.001 — job TTL configuration
- CTL.K8S.AUTH.ACCESSKEYMAP.001 — identity mapping
- CTL.K8S.KUBELET.HOSTNAME.001 — hostname override
- CTL.K8S.KUBELET.ROTATE.SERVER.001 — server cert rotation
