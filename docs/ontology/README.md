# Stave Security Graph Ontology

Standards-based ontology mapping for Stave's security graph.
Every concept maps to an existing standard where one exists.
Stave extensions use the host standard's `x_` prefix convention.

## Standards Adopted

| Standard | Version | Use in Stave | License |
|---|---|---|---|
| [OCSF](https://schema.ocsf.io) | v1.3+ | Findings, resources, identities, remediation | Apache 2.0 / Linux Foundation |
| [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) | 2.1 | Chains, attack patterns, threat indicators | OASIS Open / Apache 2.0 |
| [MITRE ATT&CK](https://attack.mitre.org) | v15+ | Attack stage taxonomy (tactic IDs) | Apache 2.0 |
| [OSCAL](https://pages.nist.gov/OSCAL/) | 1.1.2 | Controls, compliance profiles, assessment results | NIST / Public Domain |

## Node Types

| Stave Concept | Standard | Standard Type | Notes |
|---|---|---|---|
| TenantScope (account) | OCSF | `cloud.account` object | Provider-agnostic account boundary |
| StorageResource | OCSF | `Infrastructure / storage` | S3, Azure Blob, GCS |
| ComputeResource | OCSF | `Infrastructure / server` | Lambda, EC2, Azure Function |
| NetworkResource | OCSF | `Infrastructure / network` | VPC, subnet, security group |
| DataResource | OCSF | `Infrastructure / database` | RDS, DynamoDB, Cosmos DB |
| SecretResource | OCSF | `Infrastructure / service` | KMS, Secrets Manager |
| Identity | OCSF | `User` or `Service Account` | IAM role/user, Azure AD SP, GCP SA |
| AccessPolicy | OCSF | `Policy` object (extension) | IAM policy document |
| Control | OSCAL | `control` | Invariant definition |
| Finding | OCSF | `Security Finding` (class 2001) | Control evaluation result |
| ThreatChain | STIX 2.1 | `Attack Pattern` SDO | Compound threat definition |
| ChainFinding | STIX 2.1 | `Indicator` SDO | Fired chain instance |
| ComplianceRequirement | OSCAL | `control` reference | Regulatory requirement |
| AttackerCapability | STIX 2.1 | `Attack Pattern` + `x_mitre_tactic_type` | Chain terminus |
| RemediationAction | OCSF | `Remediation Activity` (class 9001) | Structured remediation spec |

## Edge Types

| Stave Concept | Standard | Standard Relationship | Notes |
|---|---|---|---|
| CAN_IMPERSONATE | STIX 2.1 | `uses` relationship | Identity can assume another identity |
| HAS_EFFECTIVE_ACCESS | OCSF | `actor` to `resource` in Finding | Resolved NEP access |
| GOVERNED_BY | OCSF | `Policy` to resource | Access policy covers resource |
| TARGETS | OCSF | Finding `resources` array | Finding targets a resource |
| MEMBER_OF | STIX 2.1 | Indicator `indicates` AttackPattern | Finding contributes to chain |
| MAPS_TO | OSCAL | Control `reference` | Control maps to requirement |
| BELONGS_TO_SCOPE | OCSF | `cloud.account` | Resource belongs to account |
| PRODUCES | STIX 2.1 | AttackPattern `kill_chain_phases` | Chain produces attacker capability |
| VIOLATES | OCSF | Finding `compliance` array | Finding violates requirement |

## Attack Stage to ATT&CK Tactic Mapping

| Stave attack_stage | ATT&CK Tactic ID | ATT&CK Tactic Name |
|---|---|---|
| initial_access | TA0001 | Initial Access |
| execution | TA0002 | Execution |
| persistence | TA0003 | Persistence |
| privilege_escalation | TA0004 | Privilege Escalation |
| detection_evasion | TA0005 | Defense Evasion |
| credential_access | TA0006 | Credential Access |
| discovery | TA0007 | Discovery |
| lateral_movement | TA0008 | Lateral Movement |
| collection | TA0009 | Collection |
| exfiltration | TA0010 | Exfiltration |
| impact | TA0040 | Impact |
| resilience | x_stave_resilience | Stave extension (no ATT&CK equivalent) |

## Resource Class Taxonomy

Provider-agnostic resource classification. Each resource has a
`resource_class` from this taxonomy and a provider-specific `provider_type`.

| resource_class | Description | AWS | Azure | GCP |
|---|---|---|---|---|
| `storage` | Object/blob storage | S3 | Blob Storage | Cloud Storage |
| `database` | Managed databases | RDS, DynamoDB | Cosmos DB, SQL | Cloud SQL, Spanner |
| `compute` | Serverless functions | Lambda | Functions | Cloud Functions |
| `instance` | Virtual machines | EC2 | Virtual Machines | Compute Engine |
| `container` | Container workloads | ECS, EKS | AKS, ACI | GKE |
| `network` | Network controls | VPC, SG, NACL | VNet, NSG | VPC, FW |
| `identity` | IAM entities | IAM role/user | Azure AD SP | Service Account |
| `key` | Encryption keys | KMS | Key Vault | Cloud KMS |
| `secret` | Secrets storage | Secrets Manager | Key Vault secrets | Secret Manager |
| `cdn` | Content delivery | CloudFront | Front Door | Cloud CDN |
| `dns` | DNS services | Route53 | DNS | Cloud DNS |
| `registry` | Container registries | ECR | ACR | Artifact Registry |
| `queue` | Message queues | SQS, SNS | Service Bus | Pub/Sub |
| `log` | Logging services | CloudTrail, CWL | Monitor | Cloud Logging |

## Stave Extensions

Concepts with no existing standard use the `x_stave_` prefix.
See `extensions.json` for JSON Schema definitions.

| Extension | Host Standard | Purpose |
|---|---|---|
| `x_stave_invariant` | OCSF Security Finding | Control predicate metadata |
| `x_stave_blast_radius` | OCSF Security Finding | Risk amplifier scope and reach |
| `x_stave_chain_membership` | OCSF Security Finding | Chain attribution per finding |
| `x_stave_tactic` | MITRE ATT&CK | Resilience tactic (no ATT&CK equivalent) |

## Machine-Readable Files

| File | Contents |
|---|---|
| `mapping.json` | Concept-to-standard mapping table |
| `extensions.json` | JSON Schema for all Stave extensions |
| `attack-stages.json` | ATT&CK tactic ID mapping |
| `resource-classes.json` | Resource class taxonomy |
| `examples/finding.ocsf.json` | OCSF Security Finding with extensions |
| `examples/chain.stix.json` | STIX Attack Pattern for a chain |
| `examples/assessment.oscal.json` | OSCAL assessment results fragment |
