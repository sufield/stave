# Stave JSON contracts

Stave is a planner. It produces retention plans, inventory reports,
quality assessments, and recommendations — but never modifies the
filesystem itself. External tools consume Stave's JSON output and
execute the recommended actions.

These JSON Schemas (draft 2020-12) document the per-entry shapes
external tools should pin against:

| Schema file | Command | What it describes |
|---|---|---|
| [`snapshot-plan.schema.json`](./snapshot-plan.schema.json) | `stave snapshot plan --format json` | Per-file retention plan: `keep` vs `delete` recommendation, age, tier, reason. |
| [`snapshot-inventory.schema.json`](./snapshot-inventory.schema.json) | `stave snapshot inventory --format json` | Per-file inventory with quality + retention signals: `keep`/`archive`/`delete`/`review`. |

Both schemas are validated against live command output by Go tests
in `cmd/prune/snapshot/plan_contract_test.go` and
`cmd/prune/inventory/inventory_contract_test.go`. CI runs them on
every push, so a contract break surfaces as a failed test before any
external tool sees the drift.

## Versioning policy

The schemas above are **stable contracts**. Once a field appears in
this directory it is bound by these rules:

* **Additive change is always allowed.** Stave may add new fields to
  any entry at any time. Consumers MUST tolerate fields they do not
  recognise (the schemas declare `additionalProperties: true` to
  document this).
* **Removing or renaming a field is a breaking change.** It is not
  permitted on the existing schema id. If the change is unavoidable,
  the command grows a `--schema-version` flag and the schema is
  re-released under a versioned id (e.g. `snapshot-plan.v2.schema.json`)
  alongside the original.
* **Tightening a field's type is a breaking change.** Widening
  (e.g. adding a new enum value) is allowed. Narrowing (e.g.
  removing an enum value, changing `string` to `integer`) requires
  the same versioned-schema treatment as a rename.
* **Behavioural changes that don't alter the JSON shape are not
  governed by this contract.** E.g. tightening the `older_than`
  threshold default in the planning logic does not break the
  schema, even though it changes which files come out as `delete`.

External tools should pin to the `$id` URL in each schema for
JSON-Schema-driven validation, and should be permissive about
unknown fields so additive changes don't require an integrator
rebuild.

## How to contribute a new contract

1. Add the field to the relevant Go DTO with a JSON tag.
2. Update the schema file in this directory: add the property,
   include a `description`, and add the field name to `required` if
   it is always present.
3. Update the contract test in `cmd/prune/...` so the new field is
   asserted on the live command output.
4. Add a section to the integration how-to in
   `docs/how-to/integrate-snapshot-lifecycle.md` if external tools
   benefit from a worked example.
