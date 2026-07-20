# Miscellaneous Domain Files

Contract fields for small namespaces that don't warrant their own file,
plus the compliance-expansion table listing additional AWS asset types
added for HIPAA / CIS / SOC 2 / PCI-DSS / NIST / FedRAMP / GDPR / FFIEC /
ISO 27001 coverage.

Part of the [observation contract](README.md).

Covered namespaces:
- `loadbalancer.*` — ELB (ALB / NLB)
- `dns.*` — DNS records (vendor-agnostic)
- `cdn.*` — CDN origin takeover detection (storage-side view of CDN
  coupling is in [storage.md](storage.md))
- `cryptography.*` — KMS key concentration and cross-domain isolation
- `secret.blast_radius.*` — Secrets Manager secret blast radius
- `backup.recovery_isolation.*` — AWS Backup recovery-isolation facts
- Plus the full compliance-expansion table covering messaging, log_group,
  monitoring, compliance, api, cache, identity (cognito), backup,
  threat_detection, security_hub, infrastructure, scaling, dns_service,
  access_analyzer, and identity blast-radius / supply-chain trust
  extensions that attach to existing namespaces

## DNS Domain
## DNS Domain (dns.*)

DNS record evaluation is **vendor-agnostic**. The controls evaluate
`properties.dns.*` regardless of whether the DNS is hosted on Route53,
Cloudflare, Namecheap, GoDaddy, or a self-hosted nameserver. The
`vendor` field on the asset is extractor metadata — controls never
reference it.

### DNS record (`dns_record`)

| Field | Type | Description |
|-------|------|-------------|
| `dns.hostname` | string | The FQDN (e.g., `a2.bime.io`) |
| `dns.record_type` | string | Record type (`CNAME`, `A`, `ALIAS`, `AAAA`) |
| `dns.target` | string | What the record points to |
| `dns.target_type` | string | Target category (`cloud_storage`, `cdn`, `compute`, `paas`) |
| `dns.target_provider` | string | Target cloud provider (`aws`, `gcp`, `azure`, `heroku`) |
| `dns.target_exists` | bool | Target resource exists |
| `dns.target_owned` | bool | Target resource is owned by the organization |
| `dns.blast_radius` | string | Impact category (`software_distribution`, `web_content`, `api`) |

**Vendor field:** Set `vendor` to whatever DNS provider hosts the zone
(`route53`, `cloudflare`, `namecheap`, `godaddy`, `bind`, etc.). Controls
evaluate `dns.*` properties only — the vendor is for provenance tracking.

---


## ELB Domain
## ELB Domain (loadbalancer.*)

### Load Balancer (`aws_elb`)

| Field | Type | Description |
|-------|------|-------------|
| `loadbalancer.kind` | string | `"alb"` or `"nlb"` — discriminator |
| `loadbalancer.encryption.tls_1_2_or_higher` | bool | HTTPS listener uses TLS 1.2+ policy |
| `loadbalancer.encryption.http_to_https_redirect` | bool | Port 80 redirects to HTTPS |
| `loadbalancer.logging.access_log_enabled` | bool | Access logging to S3 enabled |
| `loadbalancer.availability.cross_zone_enabled` | bool | Cross-zone load balancing enabled |

---


## Additional domains (compliance expansion)

These domains were added for HIPAA, CIS, SOC 2, PCI-DSS, NIST, FedRAMP,
GDPR, FFIEC, and ISO 27001 compliance coverage. Each follows the same
`properties.{namespace}.kind` discriminator pattern.

| Asset Type | Namespace | Kind | Key Properties |
|---|---|---|---|
| `aws_cloudtrail_trail` | `audit_trail.*` | `trail` | `multi_region_enabled`, `log_file_validation_enabled`, `encryption.*`, `s3_data_events.*` |
| `aws_kms_key` | `cryptography.*` | `key` | `key_rotation_enabled`, `origin`, `policy.has_wildcard_principal`, `key_isolation.*` (derived) |
| `aws_secretsmanager_secret` | `secret.*` | `secret` | `encryption.customer_managed_key`, `access.rotation_enabled` |
| `aws_dynamodb_table` | `database.*` | `table` | `encryption.sse_type`, `encryption.sse_enabled` |
| `aws_sqs_queue` | `messaging.*` | `queue` | `encryption.encrypted`, `dead_letter_queue.enabled` |
| `aws_sns_topic` | `messaging.*` | `topic` | `encryption.encrypted` |
| `aws_cloudwatch_log_group` | `log_group.*` | `log_group` | `has_retention_policy`, `retention_days` |
| `aws_cloudwatch_monitoring_config` | `monitoring.*` | `account` | `metric_filters.*.exists`, `alarms.*.exists` |
| `aws_config_recorder` | `compliance.*` | `recorder` | `recording_enabled`, `all_resource_types`, `has_active_rules` |
| `aws_apigateway_stage` | `api.*` | `rest_api`, `http_api` | `encryption.tls_enforced`, `encryption.minimum_tls_version`, `encryption.cache_encrypted`, `logging.access_log_destination`, `logging.access_log_dest_exists`, `logging.has_ghost_log_dest`, `endpoint.api_id`, `endpoint.default_endpoint_enabled`, `endpoint.has_custom_domain`, `network.endpoint_type` (PRIVATE/REGIONAL/EDGE), `network.is_private`, `network.resource_policy_restricts_vpc`, `network.allowed_vpce_ids`, `network.allowed_vpc_ids`, `security.client_certificate_enabled`, `security.client_certificate_configured`, `security.client_certificate_expired`, `security.client_certificate_expiry_days`, `throttle.has_usage_plan`, `throttle.usage_plan_count`, `cache.enabled`, `cache.ttl`, `cache.ttl_default` |
| `aws_apigateway_vpc_link` | `api.vpc_link.*` | `apigateway_vpc_link` | `id`, `target_arn`, `target_exists`, `has_ghost_target`, `status` |
| `aws_apigateway_integration` | `api.integration.*` | `apigateway_integration` | `api_id`, `route_key`, `lambda_arn`, `lambda_exists`, `has_ghost_lambda`, `type` (HTTP/HTTP_PROXY/AWS/AWS_PROXY/MOCK), `uri`, `uses_http`, `uses_https`, `has_vpc_link`, `backend_appears_private`, `lambda_permission_scoped`, `lambda_source_arn_pattern`, `timeout_ms`, `timeout_at_maximum` |
| `aws_apigateway_stage` (vars + lifecycle) | `api.stage.*` | `apigateway_stage` | `name`, `is_default`, `auto_deploy`, `appears_nonprod`, `backend_appears_prod`, `cross_env_backend`, `has_credential_vars`, `credential_var_keys`, `variable_count`, `has_ghost_vars`, `ghost_var_keys`, `ghost_var_arns` |
| `aws_apigateway_authorizer` | `api.authorizer.*` | `apigateway_authorizer` | `id`, `type` (TOKEN/REQUEST/COGNITO/JWT), `provider_arn`, `provider_exists`, `has_ghost_provider`, `jwt.issuer`, `jwt.audience`, `jwt.audience_configured`, `jwt.issuer_uses_http`, `referenced_by_routes`, `is_orphaned` |
| `aws_apigateway_custom_domain` | `api.custom_domain.*` | `apigateway_custom_domain` | `certificate_arn`, `certificate_exists`, `certificate_expired`, `certificate_expiry_days`, `has_ghost_cert`, `mtls_enabled`, `mtls_truststore_uri`, `mtls_truststore_exists`, `has_ghost_truststore` |
| `aws_apigateway_usage_plan` | `api.usage_plan.*` | `apigateway_usage_plan` | `api_key_ids`, `has_ghost_keys`, `ghost_key_ids` |
| `aws_apigateway_method` | `api.method.*` | `apigateway_method` | `route_key`, `api_key_required`, `has_authorizer`, `api_key_sole_auth`, `has_validator`, `validator_type` (NONE/BODY/PARAMS/BODY_AND_PARAMS), `validates_body`, `validates_params` |
| `aws_apigateway_websocket_api` | `api.access.*`, `api.websocket.*` | `websocket_api` | `connect_route_authorized`, `connect_route_authorizer_id`, `default_route_exists`, `default_route_validates`, `route_count`, `throttle_configured`, `connection_limit`, `message_rate_limit` |
| `aws_apigateway_response` | `api.response.*` | `rest_api` (response config) | `gateway_responses_customized`, `default_responses_active`, `exposes_server_header` |
| `aws_apigateway_lifecycle` | `api.lifecycle.*` | `rest_api`, `http_api` (lifecycle facets) | `has_custom_domain`, `last_deployment_days`, `appears_unused`, `deployment_count` |
| `aws_elasticache_cluster` | `cache.*` | `cluster` | `encryption.in_transit_enabled`, `encryption.at_rest_enabled` |
| `aws_cognito_user_pool` | `identity.*` | `user_pool` | `auth.mfa_enforced`, `auth.mfa_configuration` |
| `aws_backup_resource` | `backup.*`, `availability.*`, `replication.*` | `resource` | `has_backup`, `is_recent`, `encrypted`, `multi_az`, `cross_region_enabled` |
| `aws_guardduty_detector` | `threat_detection.*` | `detector` | `enabled` |
| `aws_securityhub` | `security_hub.*` | `hub` | `enabled` |
| `aws_cloudformation_stack` | `infrastructure.*` | `stack` | `drift_detection_enabled` |
| `aws_autoscaling_group` | `scaling.*` | `auto_scaling_group` | `availability_zone_count` |
| `aws_route53_zone` | `dns_service.*` | `hosted_zone` | `health_checks_configured` |
| `aws_network_acl` | `network.*` | `nacl` | `allows_admin_from_internet` |
| `aws_access_analyzer` | `access_analyzer.*` | — | `enabled`, `analyzer_type` |

---


## Identity blast radius extensions

Additional properties for the existing `identity.role.*` namespace:

| Property | Type | Description |
|---|---|---|
| `identity.role.sensitive_resource_count` | int | Sensitive resources (PHI/PII/confidential) reachable |

Parallel properties for the `identity.user.*` namespace:

| Property | Type | Description |
|---|---|---|
| `identity.user.reachable_resources_count` | int | Resources reachable through user's attached and inline policies |
| `identity.user.sensitive_resource_count` | int | Sensitive resources (PHI/PII/confidential) reachable |

**Controls:** CTL.IAM.IDENTITY.BLASTRADIUS.004 (role sensitive > 20),
CTL.IAM.IDENTITY.BLASTRADIUS.005 (user reachable > 50),
CTL.IAM.IDENTITY.BLASTRADIUS.006 (user sensitive > 20).

---

## Supply chain trust namespace

The `identity.trust.oidc.*` namespace tracks OIDC federation trust
policies on IAM roles used by CI/CD pipelines.

| Property | Type | Description |
|---|---|---|
| `identity.trust.oidc.has_oidc_trust` | bool | Role trusts an OIDC identity provider |
| `identity.trust.oidc.provider` | string | `github`, `gitlab`, `bitbucket`, `google` |
| `identity.trust.oidc.sub_claim_scoped` | bool | Subject claim restricted to specific repo/branch |
| `identity.trust.oidc.sub_claim_value` | string | The actual sub condition value |
| `identity.trust.oidc.has_wildcard_sub` | bool | Subject claim uses wildcard (`*`) |
| `identity.trust.oidc.has_admin_permissions` | bool | Role has AdministratorAccess or wildcard actions |

**Controls:** CTL.IAM.TRUST.OIDC.001 (unscoped trust), .002 (wildcard sub),
.003 (admin permissions).

---

## Secret blast radius namespace

The `secret.blast_radius.*` namespace links secrets to the resources
they unlock and tracks the access surface.

| Property | Type | Description |
|---|---|---|
| `secret.kind` | string | Discriminator: `secret` |
| `secret.blast_radius.target_resource_id` | string | ARN of the resource the secret provides credentials for |
| `secret.blast_radius.target_sensitivity` | string | `phi`, `pii`, `confidential`, `public`, `none` |
| `secret.blast_radius.privileged_reader_count` | int | Principals with secretsmanager:GetSecretValue |
| `secret.blast_radius.access_vector` | string | `same_account`, `cross_account` |
| `secret.blast_radius.is_rotated` | bool | Secret has been rotated recently |

**Controls:** CTL.SECRET.BLAST.001 (multiple readers + sensitive target),
.002 (cross-account + sensitive target).

---

## Recovery isolation namespace

The `backup.recovery_isolation.*` namespace tracks whether backup
recovery is independent of the source data's fate.

| Property | Type | Description |
|---|---|---|
| `backup.kind` | string | Discriminator: `resource` |
| `backup.recovery_isolation.kms_same_account_as_source` | bool | Encryption key in same account as data |
| `backup.recovery_isolation.kms_key_account` | string | Account holding the backup encryption key |
| `backup.recovery_isolation.data_account` | string | Account holding the source data |
| `backup.recovery_isolation.admin_is_shared` | bool | Same principal can delete data AND key |

**Controls:** CTL.BACKUP.RECOVERY.ISOLATION.001 (KMS same account),
.002 (shared admin — ransomware path).

---


## KMS concentration namespace

The `cryptography.key_concentration.*` namespace tracks the resource
density per KMS key.

| Property | Type | Description |
|---|---|---|
| `cryptography.kind` | string | Discriminator: `key` |
| `cryptography.key_concentration.resource_count` | int | Resources encrypted with this key |
| `cryptography.key_concentration.has_deletion_protection` | bool | Key has deletion protection enabled |

**Controls:** CTL.KMS.CONCENTRATION.001 (>50 resources),
.002 (high density + no deletion protection).

---

## KMS key isolation namespace

The `cryptography.key_isolation.*` namespace tracks whether a KMS key
is shared across data classification domains. These properties are
**derived by the Stave assessor** during evaluation (not by the
extractor) by cross-referencing `cryptography.kms_key_id` and
`tags.data-classification` across all assets in the snapshot.

The extractor must supply `cryptography.kms_key_id` on each resource
and `tags.data-classification` (phi, cde, confidential, internal,
public, non-sensitive) for isolation analysis. Resources missing the
classification tag are treated as `unclassified`.

| Property | Type | Description |
|---|---|---|
| `cryptography.key_isolation.is_exclusive_to_domain` | bool | Key encrypts resources within a single sensitivity level |

**Sensitivity hierarchy** (highest to lowest):
`phi`/`cde` > `confidential` > `internal` > `public`/`non-sensitive` > `unclassified`

**Controls:** CTL.KMS.ISOLATION.001 (key shared across sensitivity
domains — cryptographic boundary collapse).

---

