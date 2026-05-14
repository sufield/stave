# Observation Contract Audit

## Date: 2026-05-14

## Premise

A set of upcoming implementation prompts assumed that Stave needs new
work to (1) author an observation JSON schema, (2) add input
validation, and (3) document the snapshot format. Before implementing
anything, this audit catalogs what already exists, what is partial,
and what is genuinely missing — so the prompts can be corrected
against reality.

**Headline:** the schema, the validation pipeline, the standalone
validate command, and the documentation set are all already in tree
and live in the apply path. The three implementation prompts would
have duplicated existing infrastructure.

## What already exists

### Schema / Contract — ✅ Shipping

- **JSON Schema files for the observation contract:**
  - `schemas/observation/v1/observation.schema.json` (Draft 2020-12,
    `urn:stave:schema:observation:v1`, accepts both `obs.v1` and
    `obs.v0.1` schema_version strings)
  - `internal/contracts/schema/embedded/observation/v1/observation.schema.json`
    (compile-time embedded copy — written by `make build`'s
    `sync-schemas` step)
  - Companion schemas for `control/v1`, `finding/v1`, `output/v1`,
    `diagnose/v1` — all paralleled under `schemas/` + `embedded/`
  - Auxiliary contract schemas: `docs/contracts/snapshot-inventory.schema.json`,
    `docs/contracts/snapshot-plan.schema.json`, the ontology v0.1
    family under `docs/ontology/v0.1/`

- **Required-field declarations** (from `observation.schema.json`):
  `schema_version`, `captured_at`, `assets`. `schema_version` is an
  enum constrained to `["obs.v1", "obs.v0.1"]`. `captured_at` carries
  `format: date-time`. `additionalProperties: false` at the root.

- **Go struct definitions** with `json` tags forming the implicit
  Go-side contract:
  - `asset.Snapshot` at `internal/core/asset/snapshot.go`
  - `asset.Asset`, `asset.CloudIdentity` (sibling types)
  - `asset.GeneratedBy` (carries `source_type`, `tool`, `tool_version`,
    `provider`)
  - `evaluation.Finding` at `internal/core/evaluation/finding.go`

- **Documentation set** at `docs/contract/` — the monolithic
  observation contract was split by namespace in April 2026 into
  ten domain-specific files: `storage.md`, `identity.md`,
  `reachability.md`, `cors.md`, `network.md`, `compute.md`,
  `database.md`, `kubernetes.md`, `misc.md`, plus `README.md`.
  The legacy aggregator `docs/observation-contract.md` redirects to
  the split set.

- **Snapshot-model rationale** at `docs/explanation/snapshot-model.md`
  explains why Stave reads files (air-gap constraint, deterministic
  output, CI-friendliness).

### Validation on load — ✅ Shipping

- **The observation loader validates every snapshot file before
  unmarshalling**, via the pipeline at
  `internal/adapters/observations/loader_core.go:126-149`:

  ```go
  // process is the single processing pipeline: validate → unmarshal → hash.
  func (l *ObservationLoader) process(data []byte, source string) (asset.Snapshot, string, error) {
      issues, err := l.validator.ValidateObservationJSON(data, contractvalidator.WithPrefix(source))
      if err != nil { ... }
      if issues.Failed() { ... return ErrSchemaValidationFailed }
      // (warnings logged but not fatal)
      var snap asset.Snapshot
      if err := json.Unmarshal(data, &snap); err != nil { ... }
      if err := normalizeSnapshotTypes(&snap); err != nil { ... }
      ...
  }
  ```

- **The schema validator** lives at
  `internal/contracts/validator/schema.go` and uses
  `github.com/santhosh-tekuri/jsonschema/v6` against the embedded
  Draft 2020-12 schema. It returns rich `Diagnostic` objects with
  path + message + kind.

- **Sentinel errors** for malformed input:
  - `contractvalidator.ErrSchemaValidationFailed` (schema-level)
  - `observations.ErrNilSnapshot` (post-unmarshal sanity)
  - `observations.ErrMissingTimestamp` (`captured_at` zero/absent)
  - `kernel.AssetType` enforces a lowercase + `[a-z0-9_.-]` regex
    pattern at `NewAssetType`, rejecting garbage type strings.

- **Connector manifest** at `internal/app/capabilities/manifest.go`
  lists the supported `generated_by.source_type` values
  (`aws-s3-snapshot`, `aws-iam-snapshot`, `aws-opensearch-snapshot`,
  `aws-vpc-snapshot`, `aws-rds-snapshot`, `aws-ecr-snapshot`,
  `aws-waf-snapshot`, `gcp-gcs-snapshot`, `dns-record-snapshot`, …).
  `capabilities.IsConnectorSupported` enforces the list at evaluation
  time. Unknown sources are rejected with a clear "use
  `--allow-unknown-input` to skip" hint.

### Standalone validate command — ✅ Shipping

`stave validate` (entry point at `cmd/apply/validate/`) is a
fully-featured pre-evaluation linter:

```
stave validate --help
What it checks:
  - Control schema (id, name, description)
  - Observation schema and timestamps
  - Cross-file consistency and time sanity
  - Duration format and feasibility

Flags include:
  --in PATH | -            single input file or stdin
  --kind control|observation|finding
  --schema-version override
  --max-unsafe duration
  --now RFC3339
  --format text|json
  --strict                 warnings → errors
  --fix-hints              remediation prose
```

The single-file mode (`--in`) plus the `--kind`/`--schema-version`
flags are exactly the schema-conformance tools the upcoming prompt
proposed creating.

### Observation type registry — ⏳ Partial

- **`kernel.AssetType` is an open string with a regex guard**
  (`^[a-z0-9][a-z0-9_.-]*$`). There is no closed enum. The
  catalog implicitly defines the vocabulary: any type appearing
  in a control's `applicable_asset_types` is "known" to that
  control, and the runtime fires controls whose
  `AppliesToAssetType(observed)` returns true.
- **No per-asset-type property schema exists today** beyond what
  the YAML controls declare (`observation_fields`, each control's
  predicate field references). Cross-control "all aws_s3_bucket
  assets must carry X, Y, Z" expectations are not formalized.
- **Connector manifest** (Section above) is a registry of known
  collectors; it does not declare which asset types each collector
  emits.

### Mapping documentation — ✅ Shipping

- **Per-domain extractor guides** at `docs/extractor-*.md`:
  `escalation`, `prompt`, `reachability`, `cross-env`, `supply-chain`,
  `exfiltration`. Plus the top-level `docs/extractor-prompt.md`
  meta-prompt that generates a complete extractor for the obs.v0.1
  schema across 74 service domains.
- **Steampipe integration guide** at
  `docs/how-to/generate-snapshots/steampipe.md`.
- **Quickstart for own data** at `docs/quickstart-own-data.md`
  documents the bundled `scripts/aws-snapshot.sh` collector and its
  output shape.
- **IAM permission requirements** at
  `docs/security/iam-minimum-s3-observation.md` lists the AWS CLI
  commands the bundled collector calls and the corresponding IAM
  actions.
- **CORS observation requirements** at
  `docs/project/cors-observation-requirements.md` documents the
  cross-service CORS property shape.

### Readiness / coverage — ✅ Shipping (just landed)

- **`stave readiness`** — added 2026-05-14 (commit `e3ea6b6be`).
  Reports catalog effectiveness: which controls and chains can fire
  against the observed asset surface, and which missing asset types
  would unlock the most coverage. Honest about the 81% of controls
  that declare no `applicable_asset_types` (bucketed as
  "indeterminate"). See `cmd/readiness/` and `internal/app/readiness/`.
- **`stave apply --dry-run`** — separately answers the schema-validity
  side: "will this input load and pass readiness checks?" Wired
  through `internal/core/schemaval/assessment.go` (`ReadinessAssessment`
  type with `IsReady`/`NextCommand`/`Findings`).
- **Coverage statistics in apply output JSON** — every `stave apply`
  result carries a `coverage_posture` block keyed by alternative
  detection tool (e.g., `prowler`) showing per-domain control
  presence, plus a `summary` block with `exposed_resources`,
  `total_assets`, `violations`.

## Malformed input behavior

Tested with the current `./stave` build (commit `e3ea6b6be`):

| Input | Expected | Actual | Correct? |
|---|---|---|---|
| Empty JSON `{}` | Error + exit 2 | exit 2, `missing required: schema_version` | ✅ |
| Missing top-level fields (`schema_version` + `captured_at` only) | Error + exit 2 | exit 2, `missing property 'assets'` | ✅ |
| Wrong type for `properties` (string instead of object) | Error + exit 2 | exit 2, `/assets/0/properties: got string, want object` | ✅ |
| Unknown `source_type` (no flag) | Error + exit 2 | exit 2, `unsupported source_type "unknown.source" (use --allow-unknown-input to skip)` | ✅ |
| Unknown `source_type` WITH `--allow-unknown-input` | Evaluate + exit 0 if compliant | exit 0, "No violations found" | ✅ |
| Valid observation | Evaluate + exit 0 or 3 | exit 3 (violations found on the CloudFront fixture) | ✅ |

All malformed inputs exit 2 (input error per CLAUDE.md's exit-code
contract). The valid path exits 0 on compliance or 3 on violations.
The "exit 0 on malformed obs" regression the upcoming brief
anticipated does not exist in the current build.

## What the three implementation prompts assumed doesn't exist

| Assumption | Reality |
|---|---|
| No JSON Schema files | **Exist.** Five schemas under `schemas/<kind>/v1/`, mirrored under `internal/contracts/schema/embedded/`, plus the ontology v0.1 family and the snapshot-plan/inventory contracts under `docs/contracts/`. |
| No validation on observation load | **Exists.** `ObservationLoader.process` calls `ValidateObservationJSON` on every snapshot before unmarshal; failure short-circuits with `ErrSchemaValidationFailed`. |
| No standalone validate command | **Exists.** `stave validate` with `--in`, `--kind`, `--schema-version`, `--strict`, `--fix-hints` is fully wired. |
| No mapping docs | **Exist.** Six extractor guides under `docs/extractor-*.md`, plus the Steampipe how-to, the bundled collector, the IAM minimum-permission tables, and `docs/extractor-prompt.md` for new collectors. |
| No readiness assessment | **Exists.** `stave readiness` (catalog-effectiveness, just landed) and `stave apply --dry-run` (schema-validity). |
| Malformed obs exits 0 | **Not true.** All malformed inputs exit 2; valid inputs exit 0/3. |

## Genuinely-missing gaps the prompts could pivot to

The original prompts pointed at problems that ARE real, just not the
ones they assumed. The gap that survives the audit:

1. **No per-asset-type property contract.** `kernel.AssetType` is an
   open string; the schema validates the outer envelope but does NOT
   validate per-type property shapes. A `properties: {storage: {kind:
   "bucket", access: {public_read: "yes"}}}` (string instead of bool)
   passes outer schema validation. Today, the predicate evaluator
   surfaces the type mismatch at evaluation time, which is late and
   per-control rather than per-asset.

2. **No machine-readable mapping of control predicates → required
   observation paths.** Controls declare `observation_fields` for
   compliance-evidence extraction, but the predicate's actual reads
   (`properties.storage.controls.public_access_block.*`) are not
   indexed for tooling. The new `stave readiness` command works
   around this by reading `applicable_asset_types` instead — accurate
   for the 19% of controls that declare types, indeterminate for the
   other 81%.

3. **No intent-property registry.** The original brief named
   `data_classification`, `role-type`, `environment`, `vendor_registry`
   as the intent surface controls depend on. No registry maps these
   names to the controls that read them, so the readiness command
   cannot produce per-resource "this bucket needs data_classification"
   actions deterministically. (Same gap the readiness command
   flagged in its "Phase 2" deferral.)

4. **No formal asset-type coverage matrix** between collector
   manifest, control catalog's `applicable_asset_types`, and chains'
   member-control sets. Each layer carries fragments; nothing
   reconciles them as a tested artifact.

## Corrected scope for each implementation prompt

### Iteration 1 (Schema) — **Cancel as written**

- Already done: full observation contract schema with required
  fields, format constraints, `additionalProperties: false`,
  versioned, embedded at build time, validated on load.
- Remaining gap: per-asset-type property sub-schemas (item #1
  above). Authoring those is a large, multi-PR catalog refactor
  (one sub-schema per asset type, ~74 types) and should be scoped
  separately if pursued.
- **Revised scope:** none unless the per-type sub-schemas are
  explicitly requested.

### Iteration 2 (Validation) — **Cancel as written**

- Already done: load-time schema validation, semantic-shape
  validation (timestamp, identity kinds), standalone `stave
  validate` command with `--strict` and `--fix-hints`.
- Remaining gap: the predicate-path → required-observation-path
  index from item #2. Useful for "you authored a control reading
  `properties.foo.bar`; no observation in this snapshot carries
  that path" diagnostics. A separate concern from input
  validation.
- **Revised scope:** if a missing-path diagnostic is wanted, scope
  it as an extension to `stave diagnose` (which already has the
  failed-evaluation explanation surface), not as new validation.

### Iteration 3 (Mapping docs) — **Cancel as written**

- Already done: six per-domain extractor guides, Steampipe how-to,
  bundled AWS CLI collector + IAM permission reference, an
  LLM-driven meta-prompt for new collectors.
- Remaining gap: an indexed asset-type coverage matrix
  (item #4) — a generated table of (asset_type, declaring control
  count, declaring chain count, collector that emits it).
- **Revised scope:** add a `make docs-coverage-matrix` target that
  generates `docs/coverage-matrix.md` from the catalog +
  connector manifest. Small, automatable, sits beside the
  existing `make docs-controls` target.

## Net recommendation

Do not implement the three prompts as written. The work they
described is duplicative of shipping infrastructure. If the
underlying *intent* was "make Stave more honest about what its
collector covered," the just-landed `stave readiness` command is
the right surface; extending it (via items #2–#4) is the
productive direction, not redoing schema/validation/docs from
scratch.
