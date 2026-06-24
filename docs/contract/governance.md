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

## `ai.model_artifact.*` / `ai.model_store.*` — model supply-chain signals

Model artifact serialization safety and integrity-verification configuration.
The collector resolves a stored artifact's format (from extension, content type,
and an optional `format` tag) and a model store's S3 integrity configuration.

| Field | Type | Meaning |
|-------|------|---------|
| `ai.model_artifact.kind` | string | `model_artifact` (gate). |
| `ai.model_artifact.serialization_format` | string | Resolved format: `pickle`, `pytorch_pickle`, `joblib` (insecure — execute code on load), or `safetensors`, `onnx`, `tflite`, `protobuf`, `hdf5`, `coreml` (safe). A bare `.pt`/`.pth` resolves to `pytorch_pickle` unless a `format=safetensors` tag overrides it (fail-closed default). |
| `ai.model_store.kind` | string | `model_store` (gate). |
| `ai.model_store.object_lock_enabled` | bool | S3 Object Lock enabled on the store. |
| `ai.model_store.versioning_enabled` | bool | Bucket versioning **ENABLED** (SUSPENDED resolves to `false`). |
| `ai.model_store.checksums_configured` | bool | Per-object checksum algorithm (SHA-256/CRC) required on artifacts. |
| `ai.model_store.data_hash_recorded` | bool | SageMaker Model Package has a `ModelDataHashValue` recorded. |

Controls: `CTL.MODEL.FORMAT.INSECURE.001`, `CTL.MODEL.INTEGRITY.CONFIG.001`.

## `role.*` — MicroVM shell-auth role signals (derived)

Resolved IAM-role signals for the MicroVM shell-auth controls. The collector
resolves the role's **effective** permissions (inline + attached managed
policies + boundaries, expanding `lambda:*`), its break-glass status,
and its workload class.

| Field | Type | Meaning |
|-------|------|---------|
| `role.kind` | string | `iam_role` (gate; existing MicroVM role namespace). |
| `role.microvm_shell_auth` | bool | Role has effective `lambda:CreateMicrovmShellAuthToken` (directly or via the `lambda:*` wildcard). **Fail-loud: emit explicitly; never omit on resolution failure.** |
| `role.is_break_glass` | bool | Role is a designated break-glass role — tag `break-glass:true` or name matching `*break-glass*` / `*emergency*`. |
| `role.workload_type` | string | `agent` / `cicd` / `human` / `service` (mirrors `identity.role.workload_type`; drives the HIGH-vs-CRITICAL split). |

Controls: `CTL.LAMBDA.MICROVM.SHELLAUTH.001` (HIGH), `CTL.LAMBDA.MICROVM.SHELLAUTH.ELEVATED.001` (CRITICAL — agent/cicd).

### MicroVM auth-token constraint signals

For roles holding `lambda:CreateMicrovmAuthToken` (directly or via
`lambda:*`). The collector parses the Allow statement's Condition.

| Field | Type | Meaning |
|-------|------|---------|
| `role.microvm_authtoken_create` | bool | Role has effective `CreateMicrovmAuthToken` (incl. the `lambda:*` wildcard). |
| `role.microvm_authtoken_expiry_constrained` | bool | A policy Condition bounds the token expiration. Fail-loud: unresolved → `false`. |
| `role.microvm_authtoken_expiry_max_minutes` | number | The expiration upper bound when constrained (compared against ≤ 30). |
| `role.microvm_authtoken_port_scoped` | bool | A policy Condition constrains `allowedPorts`. Safe default: unresolved → `false`. |
| `role.microvm_authtoken_allows_lifecycle_port` | bool | The allowed-ports set includes the MicroVM's configured lifecycle hook port (must never be true for external tokens). |

Controls: `CTL.LAMBDA.MICROVM.AUTHTOKEN.EXPIRY.001`, `CTL.LAMBDA.MICROVM.AUTHTOKEN.PORTSCOPE.001`. The exact AWS condition-key names may not be published yet; the collector matches whatever AWS uses and fails loud (treats unresolved as unconstrained) so the controls flag unconstrained permissions regardless.

## `microvm.*` — Lambda MicroVM audit signals

Extends the existing `microvm.*` namespace (`microvm.kind`,
`microvm.ingress.secure`) with sensitivity and data-event coverage.

| Field | Type | Meaning |
|-------|------|---------|
| `microvm.sensitive` | bool | The MicroVM runs a sensitive workload (classification tag or account). |
| `microvm.audit.data_events_enabled` | bool | A CloudTrail trail covers the MicroVM control-plane API surface (`RunMicrovm`, `CreateMicrovmAuthToken`, `SuspendMicrovm`, `ResumeMicrovm`). |
| `microvm.is_production` | bool | The MicroVM is production — env tag `production`/`prod`, or a production account/OU. |
| `microvm.shell_ingress_connector` | bool | A launched network connector ARN matches `…:network-connector:aws-network-connector:SHELL_INGRESS` (makes shell access structurally possible). |
| `microvm.execution_role_present` | bool | The running MicroVM has an execution role (runtime logs + AWS access). |
| `microvm.build_role_present` | bool | The MicroVM's source image has a build role (build logs). |

Controls: `CTL.LAMBDA.MICROVM.DATAEVENTS.001`, `CTL.LAMBDA.MICROVM.SHELLINGRESS.001`, `CTL.LAMBDA.MICROVM.OBSERVABILITY.ROLES.001`.

### MicroVM lambda:* blast-radius signals

AWS placed the MicroVM actions in the `lambda:` IAM namespace, so `lambda:*`
(common in Lambda-heavy accounts, often predating MicroVMs) now includes all
MicroVM actions — shell/auth tokens, run, lifecycle, image creation.

| Field | Type | Meaning |
|-------|------|---------|
| `role.has_lambda_wildcard` | bool | Role has effective `lambda:*` — inline OR attached managed policy (e.g. `AWSLambda_FullAccess`) OR boundary. |
| `role.is_microvm_admin` | bool | Role is a designated MicroVM admin (tag `microvm-admin:true` or name `*microvm-admin*`). |

Controls: `CTL.LAMBDA.MICROVM.WILDCARD.001` (HIGH), `CTL.LAMBDA.MICROVM.WILDCARD.ELEVATED.001` (CRITICAL — agent/cicd).
