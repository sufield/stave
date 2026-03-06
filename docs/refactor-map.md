# Refactor Map — `internal/domain`

## File Inventory

| File | Responsibilities | Suggested Split | Target |
|------|-----------------|-----------------|--------|
| `catalog.go` | Type constants, valid domains/categories, evaluatable types | `invariant_types.go`, `control_id_taxonomy.go`, `evaluator_capabilities.go` | STEP 2 |
| `control_id.go` | ID validation | Rename `validate` → `validateControlIDFormat` | STEP 3 |
| `invariant_definition.go` | Definition struct + validation | Fix Action message | STEP 3 |
| `predicate_ops.go` | 14 operators mixed together | `operators_catalog.go`, `operators_compare.go`, `operators_strings.go`, `operators_collections.go` | STEP 4 |
| `diagnostics.go` | Types + runner + analysis + helpers (~530 lines) | `diagnostics_types.go`, `diagnostics_runner.go`, `diagnostics_analysis.go`, `diagnostics_predicate_helpers.go` | STEP 5 |
| `evaluator_findings.go` | Finding creation + S3 vendor evidence | Extract `evidence_s3.go` | STEP 6 |
| `evaluator_run.go` | Evaluate() orchestration (~160 lines) | Extract helpers into `evaluator_helpers.go` | STEP 7 |
| `predicate_ops.go` (operators) | Operator functions | Future `internal/predicate` subpackage | STEP 8 |

## Files NOT Touched

| File | Reason |
|------|--------|
| `evaluator.go` | Clean — struct + constructor only |
| `evaluator_timelines.go` | Single responsibility — timeline building |
| `finding.go` | Pure types |
| `snapshot.go` | Pure types |
| `observation.go` | Pure types |
| `unsafe_predicate_eval_context.go` | Pure types |
| `unsafe_predicate_eval.go` | Single responsibility — evaluation logic |
| `unsafe_predicate_rule.go` | Single responsibility — rule evaluation |
| `unsafe_predicate_fields.go` | Single responsibility — field extraction |
| `validate.go` | Validation orchestration |
| `validate_predicates.go` | Predicate validation |
| `id.go` | Generic ID type |
| `resource_id.go` | Resource ID type |
| `identity.go` | Identity types |
| `scope.go` | Scope types |
| `duration.go` | Duration parsing |
| `confidence.go` | Confidence computation |
| `sensitive.go` | Sensitive data handling |
| `redactable_map.go` | Redactable map type |
| `ignore.go` | Ignore rules |
| `ports.go` | Port interfaces |
| `doc.go` | Package doc |
| `invariant_store.go` | Store logic |
| `invariant_params.go` | Params type |
| `evaluator_prefix_exposure.go` | Prefix exposure logic |

## Lowest-Risk Refactors (STEPs 2-6)

1. **STEP 2** — Split `catalog.go`: pure data, zero logic, no imports
2. **STEP 3** — Rename function + fix string literal: trivial rename
3. **STEP 4** — Split `predicate_ops.go`: pure functions, no state
4. **STEP 5** — Split `diagnostics.go`: largest file, clear section boundaries
5. **STEP 6** — Extract S3 evidence: 2 functions, isolated concern
