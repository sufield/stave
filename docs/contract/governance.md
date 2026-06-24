# Governance Domain

Normalized observation properties for cross-resource governance invariants
(data classification, environment) and for new agent / MicroVM signals
introduced alongside the AICM v1.1 coverage work. A collector populates these;
Stave core only reads them.

## `governance.*` — classification & environment (any data-bearing asset)

Emitted on data-bearing assets (S3, RDS, DynamoDB, Secrets Manager, OpenSearch,
Redshift, EFS) so a single meta-control can reason about classification across
resource types without a per-service field path.

| Field | Type | Meaning |
|-------|------|---------|
| `governance.is_data_bearing` | bool | The asset stores data and is therefore in scope for classification controls. |
| `governance.data_classification` | string | Resolved classification value, normalized from whatever tag key the org uses (`data_classification`, `data-classification`, `classification`, `sensitivity`). **Absent** when no recognized tag is present. Approved taxonomy: `public`, `internal`, `confidential`, `restricted`, `pii`, `phi`, `pci`. |
| `governance.environment` | string | Resolved environment (`production`, `staging`, `development`, …) from account tag, name pattern, or org unit. |

Controls: `CTL.DATACLASS.TAG.MISSING.001`, `CTL.DATACLASS.TAG.TAXONOMY.001`,
`CTL.DATACLASS.PROD.UNTAGGED.001`.

## `identity.role.*` — agent / non-human-identity signals

Extends the `identity.*` namespace (see `identity.md`) with workload
classification used by agent-scoped controls.

| Field | Type | Meaning |
|-------|------|---------|
| `identity.role.workload_type` | string | `agent`, `human`, or `service`, classified from trust-policy principals (bedrock/sagemaker/lambda/states), name patterns (`*agent*`, `*bot*`, `*automation*`, `*pipeline*`), or a `role-type`/`workload-type` tag. |
| `identity.role.long_lived_keys_present` | bool | An active long-lived IAM access key exists for the identity (vs. STS session-only credentials). |
| `identity.agent_reaches_sensitive` | bool | **Derived (graph)**. An agent role has a transitive path (assume/pass chain or resource policy, any depth) to a sensitive resource. Computed by the reasoning spec `examples/agent-chain-sensitive-reach/` (Soufflé + Z3). |
| `identity.agent_reach_path` | string | Full hop-by-hop path behind `agent_reaches_sensitive`, used as finding evidence. |

Controls: `CTL.IAM.AGENT.LONGLIVEDKEYS.001`, `CTL.IAM.AGENT.CHAIN.SENSITIVE.001`.

## `ai.knowledge_base.*` — RAG retrieval signals (derived)

Compound signals for Bedrock Knowledge Base retrieval safety, computed by the
reasoning specs (Soufflé + Z3), read by `scope: compound` catalog controls.

| Field | Type | Meaning |
|-------|------|---------|
| `ai.knowledge_base.retrieval_broader_than_embedding` | bool | The retrieval role's effective permissions are not a strict read-only subset of the embedding role's (a broader/wildcard grant, a write action, or an extra service). Reasoning spec: `examples/rag-retrieval-vs-embedding/`. |
| `ai.knowledge_base.retrieval_exceeds_declared_scope` | bool | The retrieval role can reach a resource outside the KB's declared `dataSourceConfiguration` — via wildcard prefix, assume-role hop, or resource-based policy. Reasoning spec: `examples/rag-retrieval-scope/`. |

Controls: `CTL.BEDROCK.KB.RETRIEVAL.OVERBROAD.001`, `CTL.BEDROCK.KB.RETRIEVAL.SCOPE.001`.

## `microvm.*` — Lambda MicroVM audit signals

Extends the existing `microvm.*` namespace (`microvm.kind`,
`microvm.ingress.secure`) with sensitivity and data-event coverage.

| Field | Type | Meaning |
|-------|------|---------|
| `microvm.sensitive` | bool | The MicroVM runs a sensitive workload (classification tag or account). |
| `microvm.audit.data_events_enabled` | bool | A CloudTrail trail covers the MicroVM control-plane API surface (`RunMicrovm`, `CreateMicrovmAuthToken`, `SuspendMicrovm`, `ResumeMicrovm`). |

Control: `CTL.LAMBDA.MICROVM.DATAEVENTS.001`.
