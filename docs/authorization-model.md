# Stave authorization & sensitivity model (Phase 7 / G3)

The CIA queries (G4 Confidentiality, G5 Integrity) need answers to two
questions the access graph alone cannot answer:

1. **Who *should* access what?** (authorization)
2. **What is sensitive?** (sensitivity)

This document records the product-decision shape of those models and
the default conventions Stave ships with. Operators override the
defaults via a `stave-authorization.yaml` file at the repo root (or
passed to the extractor with `-config`).

## Headline decisions

**Two-tier sensitivity, not five.** `high` and `standard`. Five tiers
sound rigorous but kill adoption — operators stall on the boundary
cases, and the CIA query's signal-to-noise ratio degrades when the
high tier is too small or too large. Two tiers force a clean
boundary: a resource is either sensitive enough to warrant the
"unauthorized access to a high-sensitivity resource" alert path, or
it isn't.

**Tag equality for authorization, not IAM-group membership.** The
G0 observation-contract audit established that the contract has no
`aws_iam_group` asset type, so group membership isn't observable. The
auth model treats matching `Owner` / `Team` tag values on principal
and resource as the authorization signal. Operators who don't tag
principals are in fail-open mode (every principal authorized).
Operators who tag both are in the "principal P with Team=X is
authorized for any resource with Team=X" model.

**Fail-open for untagged resources; fail-closed for untagged
principals against tagged resources.** Asymmetric by design:

- Untagged resource: no ownership signal exists. Every principal
  is authorized. Avoids false-positive flood when an operator
  hasn't built up tag coverage yet.
- Tagged resource, untagged principal: the resource expressed an
  ownership; the principal didn't claim membership. The principal
  is unauthorized for this resource. This catches the "stale
  service role that predates the team-tag convention" case.

**Framework-based sensitivity deferred from G3.** The original
prompt's sensitivity model included "resources in HIPAA / PCI scope
are sensitivity: high based on framework-citing controls firing on
them." Implementing this requires running `stave apply` inside the
extractor and projecting findings → resource sensitivity, which
turns the simple G3 extractor into a pipeline-running script. G3
ships tag-based sensitivity only (the `DataClassification` tag with
`PII / PHI / PCI` values). Framework-based sensitivity is a
follow-up iteration that wraps the extractor in the validator's
shape (stave apply → findings → sensitivity facts). The
extractor's TODO marker references this doc for future work.

## Default config shape (`stave-authorization.yaml`)

```yaml
# Stave default authorization + sensitivity config.
# Override values by editing this file or passing -config <path>
# to reasoning/souffle/iam/extract.go.

authorization:
  # Tag keys whose values define ownership/team membership.
  # A principal is "authorized" for a resource iff the principal
  # and the resource carry the same value for ANY of these keys.
  #
  # Override to match your tagging convention (e.g., CostCenter,
  # Squad, BusinessUnit). Leave empty to disable authorization
  # entirely (all principal-resource pairs become authorized;
  # CIA queries effectively short-circuit).
  ownership_tag_keys:
    - Owner
    - Team

sensitivity:
  # Tag key whose values mark a resource as high-sensitivity.
  classification_tag_key: DataClassification

  # Values that, when present in classification_tag_key, mark the
  # resource as high-sensitivity. CIA queries fire on
  # (unauthorized_access × high_sensitivity) joins; expanding this
  # list expands the "what's worth alerting on" surface.
  high_values:
    - PII
    - PHI
    - PCI

  # Framework-based sensitivity (deferred to follow-up). The
  # extractor will populate resource sensitivity from framework
  # citations on the controls that fire on each resource, once the
  # extractor wraps the full stave apply pipeline. See G3 product-
  # decision doc for the deferral rationale.
  framework_keys: []
```

## Concrete examples

**Authorized — matching team tag.**
```
has_tag(arn:aws:iam::123:role/data-eng-prod, "Team=DataEng")
has_tag(arn:aws:s3:::prod-pii-bucket,        "Team=DataEng")
→ authorized(arn:aws:iam::123:role/data-eng-prod,
              arn:aws:s3:::prod-pii-bucket)
```

**Unauthorized — mismatched team tag.**
```
has_tag(arn:aws:iam::123:role/finance-prod, "Team=Finance")
has_tag(arn:aws:s3:::prod-pii-bucket,        "Team=DataEng")
→ NOT authorized(finance-prod, prod-pii-bucket)
→ if effective_access(finance-prod, prod-pii-bucket, _) holds,
   then unauthorized_access fires
```

**Fail-open — untagged resource.**
```
has_tag(arn:aws:iam::123:role/anyone, "Team=Anything")
# No Team or Owner tag on arn:aws:s3:::staging-bucket
→ authorized(anyone, staging-bucket)  (fail-open)
```

**Fail-closed — tagged resource, untagged principal.**
```
# No Team or Owner tag on arn:aws:iam::123:role/legacy-role
has_tag(arn:aws:s3:::prod-pii-bucket, "Team=DataEng")
→ NOT authorized(legacy-role, prod-pii-bucket)  (fail-closed)
```

**High sensitivity — DataClassification tag.**
```
has_tag(arn:aws:s3:::prod-pii-bucket, "DataClassification=PII")
→ sensitivity(prod-pii-bucket, "high")
```

**Standard sensitivity — no classification tag.**
```
# No DataClassification tag on arn:aws:s3:::staging-bucket
→ sensitivity(staging-bucket, "standard")
```

## Soufflé encoding

Three new base relations in `schema.dl`:

```
.decl authorized(principal_id: symbol, resource_id: symbol)
.input authorized

.decl sensitivity(resource_id: symbol, level: symbol)
.input sensitivity

// no_owner_tag: the resource has no Owner/Team tag. Used by the
// fail-open rule in the auth view.
.decl no_owner_tag(resource_id: symbol)
.input no_owner_tag
```

One new derived relation in `rules.dl`:

```
.decl unauthorized_access(principal_id: symbol, resource_id: symbol, action: symbol)
.output unauthorized_access

unauthorized_access(P, R, A) :-
    effective_access(P, R, A),
    !authorized(P, R).
```

The `authorized` and `sensitivity` facts are emitted by the G3-
extended extractor, populated from the tag conventions above.

## Why not richer ABAC for first iteration

Real-world ABAC (Attribute-Based Access Control) has principal
attributes, resource attributes, conditions, action sets, time-of-
day, source-IP, and so on. The CIA queries don't need that
richness — they need a coarse yes/no for "should this principal
touch this resource?" and a coarse high/standard for "is this
worth the critical alert?" The two-tag-key authorization model is
the floor that's useful; it's the operator's choice to lift it via
the config file.

If the CIA findings produced by G4-G5 prove too noisy because the
coarse model produces too many `unauthorized_access` rows, the
config's `ownership_tag_keys` is the lever: add more keys, change
the matching semantics. If too quiet, drop the keys. The model is
designed to scale via configuration, not via code.

## Honest limitations (recorded at G3 entry)

1. **No group-inherited authorization.** Inherited from the G0
   decision to drop `group_membership`. If a principal's
   authorization should derive from a group their AWS account
   places them in, this model doesn't see it.

2. **No multi-tag conjunction.** A resource tagged `Team=DataEng,
   Owner=Alice` authorizes anyone with Team=DataEng OR Owner=Alice,
   not (Team=DataEng AND Owner=Alice). Disjunction wins because
   conjunction-based authorization would require an explicit
   policy file beyond tag values.

3. **No deny lists.** Authorization is positive-only. If you need
   "everyone except Bob," that's a separate `deny_authorized` fact
   layer not implemented here.

4. **Framework-based sensitivity deferred** (above).

5. **Tag-key case sensitivity matches AWS** — `team` and `Team`
   are different keys. Operators should normalize at tagging time.

Each limitation is a known boundary, not a defect. Most can be
addressed via configuration changes if/when CIA findings prove
they matter.
