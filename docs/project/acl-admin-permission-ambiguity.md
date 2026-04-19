# `storage.access.public_admin` — contract/alias ambiguity

The observation contract and the predicate alias registry disagree
about what permission `storage.access.public_admin` represents. This
blocks clean implementation of a READ_ACP-specific control grounded
in the Tarun Koyalwar (May 2022) disclosure.

## The contradiction

**Contract** (`docs/contract/README.md`):

```
| storage.access.public_admin | bool | Public ACL write-ACP |
```

Defines the field as WRITE_ACP only.

**Alias registry** (`internal/builtin/predicate/aliases.go`) — two
aliases check the same field with incompatible descriptions:

| Alias | Description | Predicate |
|---|---|---|
| `S3ACLWritable` | "ACL grants write-ACP to public…" | `public_admin == true` |
| `S3ACLReadableByPublic` | "ACL read-ACP granted to the public" | `public_admin == true` |

**Controls consuming the aliases:**

- `CTL.S3.ACL.ESCALATION.001` (name: "No Public ACL Modification") →
  alias `s3.acl_writable` → description talks about WRITE_ACP and
  `PutBucketAcl`. Aligned with the contract.
- `CTL.S3.ACL.RECON.001` (name: "No Public ACL Readability") →
  alias `s3.acl_readable_by_public` → description talks about
  READ_ACP and `GetBucketAcl`. **Not aligned** — the predicate checks
  the WRITE_ACP field.

## Possible resolutions

Exactly one of these is true. The codebase does not tell me which.

1. **Contract is right, RECON is misnamed.** `public_admin` = WRITE_ACP.
   `S3ACLReadableByPublic`'s description is wrong;
   `CTL.S3.ACL.RECON.001` is a naming/description mismatch analogous
   to the `CTL.S3.PUBLIC.004` / `CTL.S3.ACL.WRITE.001` bugs fixed in
   earlier iterations. READ_ACP has never actually been detected;
   RECON is a duplicate of ESCALATION.

2. **`public_admin` is overloaded.** It's true when either READ_ACP
   OR WRITE_ACP is granted to public. The contract description is
   incomplete; the field name is generic. READ_ACP and WRITE_ACP are
   not separately distinguishable at the predicate level.

3. **Contract is wrong, ESCALATION is misnamed.** `public_admin` =
   READ_ACP. Unlikely given ESCALATION's remediation text explicitly
   names `PutBucketAcl` (the WRITE_ACP action), but strictly possible
   if the extractor convention diverges from both control names.

## Why this blocks the Tarun Koyalwar iteration

The Tarun Koyalwar disclosure (May 2022) enumerates three distinct
ACL grants to AllUsers: READ, LIST, READ_ACP. The iteration asked
for a READ_ACP-specific detection distinct from READ.

Any of the iteration's three paths depends on resolving the ambiguity
first:

- **Path A** (coverage holds) can't be claimed: the existing
  RECON.001 either catches WRITE_ACP twice (resolution 1) or catches
  a conflated signal (resolution 2). Neither is a clean READ_ACP
  detector.
- **Path B** (add a control against the existing field): which field?
  `public_admin` is ambiguous.
- **Path C** (extend the contract): the minimum extension depends on
  whether `public_admin` stays (narrowed to WRITE_ACP) or gets
  replaced by two separate booleans.

## Recommended follow-up

Pick one interpretation as authoritative and align the other two
artifacts:

1. Decide on a canonical extractor convention for the AllUsers
   READ_ACP grant — a separate boolean `storage.access.public_read_acp`
   is the cleanest shape and mirrors the existing
   `has_full_control_public` / `public_admin` pattern.
2. Update `internal/builtin/predicate/aliases.go` so
   `S3ACLReadableByPublic` checks the new field.
3. Tighten the contract description for `public_admin` to explicitly
   say WRITE_ACP only.
4. Then add the Tarun Koyalwar fixture against the clean signal.

## Related

- `CTL.S3.ACL.ESCALATION.001` — alias `s3.acl_writable`, WRITE_ACP
  detection.
- `CTL.S3.ACL.RECON.001` — alias `s3.acl_readable_by_public`,
  claims READ_ACP but predicate overlaps with ESCALATION.
- Prior naming-mismatch fixes: commits `50b5252d0`
  (`CTL.S3.ACL.WRITE.001` → `CTL.S3.POLICY.WRITE.001`) and
  `9b71fcb61` (`CTL.S3.PUBLIC.004` / `.007` / `.008` rewrites).
