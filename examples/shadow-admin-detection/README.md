# Shadow Admin Detection Demo

A role named `S3-ReadOnly` with a `role-type=readonly` tag can
retrieve any secret in the account, invoke any Lambda, and
enumerate every IAM role. No admin policy attached. Single-resource
scanners report compliant.

Two years of incremental "just this one permission" additions
turned a readonly role into a Shadow Admin — by accumulation,
not by design.

## Run

```bash
bash run.sh
```

## What it shows

1. **Individual findings** —
   `CTL.IAM.ROLE.PERMISSIONDRIFT.001` (8 of 12 services never used),
   `CTL.IAM.ROLE.CATEGORYMIX.001` (`data_read` + `secrets_access`),
   `CTL.IAM.ROLE.INTENTMISMATCH.001` (permissions contradict the
   `readonly` tag).
2. **Compound chains** —
   `shadow_admin_by_accumulation` (drift + categorymix + intent
   mismatch) and `privilege_creep_lateral_movement` (categorymix
   + drift). Both threshold-2, both `CRITICAL`.
3. **Remediation** — remove unused services, split incompatible
   categories into separate roles, update the role-type tag to
   match the actual function. Findings and chains drop to zero.

## The pitch

> "The role is named `S3-ReadOnly`. It can retrieve any secret in
> your account. Access Advisor says 8 of 12 accessible services
> have never been used. The permissions contradict the `readonly`
> tag. No admin policy attached. Your scanner reports: compliant."

## Inputs

- `fixtures/writeup-config/observations/` — the `S3-ReadOnly` role
  with pre-computed permission drift, category mixing, and intent
  mismatch fields (sourced from
  `internal/controldata/testdata/iam/role/shadow-admin/`).
- `fixtures/remediated-config/observations/` — an `AppDataReader`
  role with the drift removed, the categories aligned, and the tag
  matching reality (sourced from
  `internal/controldata/testdata/iam/role/clean-role/`).

## Controls and chains in play

- `controls/iam/entropy/CTL.IAM.ROLE.PERMISSIONDRIFT.001.yaml`
- `controls/iam/entropy/CTL.IAM.ROLE.CATEGORYMIX.001.yaml`
- `controls/iam/entropy/CTL.IAM.ROLE.INTENTMISMATCH.001.yaml`
- `controls/iam/entropy/CTL.IAM.ROLE.INTENTTAG.001.yaml`
- `controls/iam/entropy/CTL.IAM.ROLE.ENTROPY.INCOMPLETE.001.yaml`
- `chains/shadow_admin_by_accumulation.yaml`
- `chains/privilege_creep_lateral_movement.yaml`
