# Stave JSONL Export Schema

Produced by `stave export-sir --format jsonl`.

Each line is one JSON object — a single SIR fact triple — with this shape:

```json
{
  "fact_id": "<deterministic hex hash>",
  "subject": "<asset id, typically an ARN or composite id>",
  "predicate": "<relation name>",
  "object": "<value or related asset id, as a string>",
  "source": "<which projector emitted this fact: controlFacts | assetFacts | identityFacts | …>",
  "evidence": "<dotted observation field path or other provenance string>",
  "provenance": { "property_path": "...", "projector": "..." }
}
```

The interesting fields for reasoning are **`predicate`**, **`subject`**, and **`object`**. The remaining fields are provenance for debugging and audit; reasoning consumers may ignore them.

## Predicate vocabulary

The vocabulary is determined by the catalog at export time. The
projector walks every control's `unsafe_predicate` AST and emits
one predicate per leaf field reference. Common predicates:

| Predicate | Meaning |
|---|---|
| `has_type` | Asset's `type` field (e.g. `aws_iam_role`) |
| `has_severity` | A control's declared severity |
| `has_action` | An IAM role's granted action (one fact per action) |
| `has_resource` | An IAM role's granted resource (one fact per resource) |
| `can_assume` | One hop in an `sts:AssumeRole` chain |
| `trusts_service` | An IAM role trusts a service principal |
| `allows_unauthenticated` | A Cognito identity pool admits anonymous principals (object: `"true"` / `"false"`) |
| `maps_unauth_to` | A Cognito identity pool maps unauthenticated principals to a specific IAM role |
| `maps_auth_to` | A Cognito identity pool maps authenticated principals to a specific IAM role |
| `self_registration_unrestricted` | A user pool admits self-registration without restrictions |
| `has_public_read` | A bucket admits anonymous read |
| `has_public_access_blocked` | A bucket has all four PAB flags enabled |

Boolean predicates project the value as the literal string `"true"` or `"false"` (never the JSON booleans) — this preserves a uniform string sort across all engines that consume the triples.

## Closed-world assumption

If a predicate-subject pair is not in the export, the predicate is **false** for that subject. The export is the complete observed state; absence is meaningful. Reasoning consumers should not assume an absent predicate "might be true and we just didn't see it."

## Multiplicities

Several predicates can have multiple facts per subject — `has_action` and `has_resource` are the canonical examples (one role grants many actions). Reasoning consumers should index by predicate AND collect every value, not assume each (subject, predicate) is unique.
