# Contract-First Schemas

Stave provides contract-first schemas so validation can be deterministic, offline, and portable across toolchains.

Control contract `v1` uses one canonical runtime shape:
- `dsl_version: ctrl.v1`
- `id`
- `name`
- `description`
- `type`
- one of:
  - `unsafe_predicate`
  - `unsafe_predicate_alias` (expanded at load time)
- optional `remediation` (`description`, `action`, `example`)

Finding contract `v1` includes:
- control + asset + evidence + `remediation` (required)
- optional `fix_plan` (deterministic machine-readable actions)

## Schema Layout

Versioned schemas are published under:

```text
schemas/
  control/
    v1/
      control.schema.json
  observation/
    v1/
      observation.schema.json
  finding/
    v1/
      finding.schema.json
```

All schemas use JSON Schema Draft 2020-12 and include stable `$id` URN identifiers.

## Embedded Runtime Schemas

The CLI embeds schema artifacts in `internal/contracts/schema` for offline use.

Programmatic access:

```go
LoadSchema(kind, version)
```

Supported kinds: `control`, `observation`, `finding`.
Default version: `v1`.

## Validate vs Lint

Use `stave validate` for schema conformance.
Use `stave lint` for control design quality rules.

- `validate` checks structural contract validity.
- `lint` checks authoring quality and deterministic design conventions.

## Deterministic Guarantees

- Offline-only schema loading (embedded files).
- Deterministic diagnostic ordering.
- Stable, file-based lint output format: `path:line:col  RULE_ID  message`.

## Polyglot Validation

Because schemas are published as versioned JSON files, non-Go tools can validate the same contracts without Stave runtime dependencies.
