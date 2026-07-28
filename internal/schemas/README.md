# Schemas

JSON Schema definitions for Stave's data formats. Each schema is
embedded into the binary at build time and used for runtime validation.

## Schema Registry

| Schema | Path | Purpose | When Used |
|--------|------|---------|-----------|
| `control.v1` | `control/v1/control.schema.json` | Control definition YAML structure | `stave validate --type control`, control loading |
| `observation.v1` | `observation/v1/observation.schema.json` | Observation snapshot structure (`obs.v0.1`) | `stave validate --type observation`, snapshot ingest |
| Asset-type sub-schemas | `observation/v1/asset-types/*.json` | Per-asset-type property validation (109 types) | Referenced via `$ref` from the observation schema during ingest |
| `finding.v1` | `finding/v1/finding.schema.json` | Individual finding structure | `stave export findings` output validation |
| `output.v1` | `output/v1/output.schema.json` | Evaluation output envelope (`out.v0.1`) | `stave apply` JSON output validation, assessment/attestation payloads |
| `diagnose.v1` | `diagnose/v1/diagnose.schema.json` | Diagnostic report structure | `stave diagnose --format json` output validation |

## How Schemas Are Used

1. **Source of truth**: `schemas/` contains the canonical definitions.
2. **Sync**: `make sync-schemas` copies them to `internal/contracts/schema/embedded/`.
3. **Embed**: Go's `//go:embed` compiles them into the binary.
4. **Validate**: The schema registry (`internal/contracts/schema/load.go`) resolves
   kind + version to the embedded file; the validator runs JSON Schema validation
   against it at runtime.

## Versioning

All schemas currently use `v1` (mapped to `kernel.RegistryLayoutStandard`
internally). Adding a new version requires a new directory
(`<kind>/v2/`) and a registry entry in `load.go`.
