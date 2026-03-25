# Contract-First Schemas

Stave uses contract-first JSON schemas so validation is deterministic,
offline, and portable across toolchains. All schemas use JSON Schema
Draft 2020-12.

---

## Schema Versions

| Contract | Version | Schema ID |
|----------|---------|-----------|
| Control | `ctrl.v1` | `urn:stave:schema:control:v1` |
| Observation | `obs.v0.1` | `urn:stave:schema:observation:v1` |
| Output | `out.v0.1` | `urn:stave:schema:output:v0.1` |
| Finding | `v1` | `urn:stave:schema:finding:v1` |
| Diagnose | `v1` | `urn:stave:schema:diagnose:v1` |

---

## Control Contract (`ctrl.v1`)

A control defines a safety check. Required fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dsl_version` | string | yes | `"ctrl.v1"` |
| `id` | string | yes | Unique ID (e.g., `CTL.S3.PUBLIC.001`) |
| `name` | string | yes | Short human-readable name |
| `description` | string | yes | What unsafe condition this detects |
| `type` | string | yes | Check category (e.g., `unsafe_state`, `authorization_boundary`) |

One of:

| Field | Description |
|-------|-------------|
| `unsafe_predicate` | Inline predicate logic (`any`/`all` + field operators) |
| `unsafe_predicate_alias` | Named alias expanded at load time (e.g., `s3.is_public_readable`) |

Optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Control document version |
| `domain` | string | Grouping label (`exposure`, `governance`, `access`) |
| `scope_tags` | array | Applicability tags (`aws`, `s3`, `prod`) |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `compliance` | object | Framework mappings (`cis_aws_v1.4.0: "2.1.1"`) |
| `params` | object | Values for `value_from_param` in predicates |
| `exposure` | object | Exposure classification (`type` + `principal_scope`) |
| `remediation` | object | Fix guidance (`description`, `action`, `example`) |

See [Evaluation Semantics](evaluation-semantics.md) for predicate operators
and matching rules.

---

## Observation Contract (`obs.v0.1`)

A point-in-time snapshot of asset state. Structure is flat JSON (no
`"snapshots"` wrapper — the schema rejects it).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | `"obs.v0.1"` |
| `captured_at` | string | yes | RFC 3339 capture time |
| `assets` | array | yes | Asset state objects |
| `generated_by` | object | no | Extraction metadata |
| `identities` | array | no | IAM identity objects |

Each asset: `id`, `type`, `vendor`, `properties` (required), `source`
(optional).

See [Observation Contract](observation-contract.md) for the full field
dictionary.

---

## Output Contract (`out.v0.1`)

Evaluation output. Two kinds distinguished by the `kind` field:

### Evaluation output (`kind: "evaluation"`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | `"out.v0.1"` |
| `kind` | string | yes | `"evaluation"` |
| `run` | object | yes | Run metadata (tool version, timing, parameters) |
| `summary` | object | yes | Aggregate counts (violations, assets, controls) |
| `findings` | array | yes | Individual violation findings |

### Verification output (`kind: "verification"`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | `"out.v0.1"` |
| `kind` | string | yes | `"verification"` |
| `run` | object | yes | Run metadata |
| `summary` | object | yes | Before/after counts |
| `resolved` | array | yes | Findings resolved between runs |
| `remaining` | array | yes | Findings still present |
| `introduced` | array | yes | New findings since baseline |

---

## Finding Contract (`v1`)

Each finding represents a single control violation for a specific asset.

Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `control_id` | string | Control that was violated |
| `control_name` | string | Human-readable control name |
| `control_description` | string | What was detected |
| `asset_id` | string | Asset that violated the control |
| `asset_type` | string | Asset type (`storage_bucket`) |
| `asset_vendor` | string | Cloud vendor (`aws`) |
| `evidence` | object | Temporal proof of violation |
| `remediation` | object | Fix guidance |

Optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `source` | object | Source file + line reference |
| `fix_plan` | object | Machine-readable fix actions |
| `exposure` | object | Exposure classification (`type` + `principal_scope`) |
| `posture_drift` | object | Temporal pattern (`persistent`, `degraded`, `intermittent`) + episode count |

### Evidence structure

| Field | Type | Description |
|-------|------|-------------|
| `first_seen_unsafe` | string | RFC 3339 timestamp of first unsafe observation |
| `unsafe_duration_hours` | number | Hours continuously unsafe |
| `threshold_hours` | number | Max-unsafe threshold that was exceeded |
| `reason` | string | Why the asset is unsafe |
| `value` | any | Matched field value (optional) |
| `source_evidence` | array | Snapshot source references (optional) |

### Remediation structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | yes | How to fix the condition |
| `action` | string | yes | Specific action to take |
| `example` | string | no | Example command or config |

---

## Schema Layout

```text
schemas/
  control/v1/control.schema.json
  observation/v1/observation.schema.json
  output/v1/output.schema.json
  finding/v1/finding.schema.json
  diagnose/v1/diagnose.schema.json
```

## Embedded Runtime Schemas

The CLI embeds schemas in `internal/contracts/schema/embedded/` for
offline use. Programmatic access:

```go
schema.LoadSchema(kind, version)
```

Supported kinds: `control`, `observation`, `finding`, `output`, `diagnose`.

## Validate vs Lint

| Command | Purpose |
|---------|---------|
| `stave validate` | Schema conformance (structural contract validity) |
| `stave lint` | Authoring quality (design conventions, determinism) |

## Deterministic Guarantees

- Offline-only schema loading (embedded files).
- Deterministic diagnostic ordering.
- Stable lint output format: `path:line:col  RULE_ID  message`.

## Polyglot Validation

Schemas are published as versioned JSON files. Non-Go tools can validate
the same contracts without Stave runtime dependencies.
