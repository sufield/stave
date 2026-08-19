# Lab 02 — Observations

Stave never calls AWS APIs. It evaluates observations — structured snapshots
of configuration state captured at a point in time.

## The obs.v0.1 Format

Open a fixture file:

```bash
cat internal/fixtures/labs/mfa-authage/bad/2026-08-19T120000Z.json
```

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-08-19T12:00:00Z",
  "source": "deployed",
  "generated_by": {
    "source_type": "synthetic.mfa-authage"
  },
  "assets": [
    {
      "id": "arn:aws:iam::111122223333:role/MfaPresentOnly",
      "type": "aws_iam_role",
      "vendor": "aws",
      "properties": {
        "identity": {
          "kind": "role",
          "trust_policy": {
            "has_cross_account_trust": true,
            "has_mfa_condition": true,
            "has_multifactor_auth_age": false,
            "has_assumption_constraints": true
          }
        }
      }
    }
  ]
}
```

Four required top-level fields:

- **schema_version** — always `obs.v0.1`
- **captured_at** — when this snapshot was taken (RFC3339)
- **source** — where the data came from (`deployed`, `synthetic`, etc.)
- **assets** — array of resources, each with `id`, `type`, `vendor`, and `properties`

The properties bag is where security state lives. This role has MFA in its
trust policy (`has_mfa_condition: true`) but no time-bound on the MFA
(`has_multifactor_auth_age: false`). That distinction is the thread we
follow through every lab.

## Two Snapshots Required

Look at the directory:

```bash
ls internal/fixtures/labs/mfa-authage/bad/
```

```
2026-08-19T120000Z.json
2026-08-19T130000Z.json
```

Two files — two points in time, one hour apart. Stave needs at least two
snapshots to compute duration-based properties ("how long has this been
unsafe?").

## How Observations Are Created

In production, you capture raw AWS CLI output and transform it:

```bash
# doctest:skip — illustrative; raw/ does not exist in fixtures
stave transform --in raw/
```

This reshapes raw JSON (e.g., `aws iam get-role` output) into obs.v0.1
format using embedded jq filters. Collection is decoupled from evaluation.

## Verify

Open both fixture files. Confirm they have the same `assets[0].id` but
different `captured_at` timestamps.

Next: [Lab 03 — Security Properties](03-security-properties.md)
