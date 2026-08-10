# Cross-Property Contradiction Sweep Report

**Date:** 2026-08-09
**Task:** TASK-048
**Catalog size:** 3,389 controls with predicates (4,594 total embedded)
**Asset types:** 280
**Unique field paths:** 3,736

## Verdict: PASS — Zero Contradictions

No control pair exists where satisfying one (making it safe) inherently
triggers the other (making it unsafe). An adopter will never encounter
a whack-a-mole scenario where fixing one finding causes another to
appear on the same resource with no escape.

## Method

Three-pass analysis against all embedded control YAMLs:

### Pass 1: Boolean exhaustion (eq true vs eq false)

Scanned all (asset_type, field) pairs for controls where one flags
`field eq true` and another flags `field eq false`. Found **104 pairs**,
all classified as **guard patterns** — one control checks "is feature
enabled?" while the other checks "is feature enabled AND configured
incorrectly?" These never fire simultaneously because the second
control's predicate includes additional narrowing conditions in an
`all` block.

Examples of valid guard patterns found:
- `CTL.BACKUP.ENCRYPT.001` (encrypted eq false) vs `CTL.BACKUP.ENCRYPT.CMK.001` (encrypted eq true AND kms_type is AWS-managed)
- `CTL.S3.LOG.001` (logging.enabled eq false) vs `CTL.S3.LOG.RETENTION.001` (logging.enabled eq true AND retention too short)
- `CTL.OPENSEARCH.FGAC.001` (fgac_enabled eq false) vs `CTL.OPENSEARCH.FGAC.NOUSERS.001` (fgac_enabled eq true AND no users configured)

### Pass 2: String/enum contradictions

Checked for `neq X` vs `neq Y` (field must equal two different values
simultaneously) and single-leaf opposite-requirement pairs. Found **zero**.

### Pass 3: Potential duplicates

Found **1** pair sharing the same single-leaf predicate:
- `CTL.S3.PUBLIC.001` and `CTL.S3.PUBLIC.RECUR.001` both check `properties.storage.access.public_read eq true`

**Not a duplicate.** The recurrence control (`RECUR`) detects oscillation
across snapshots over time (bucket repeatedly toggling between public and
private). Same predicate field, different semantic intent — the recurrence
pattern evaluates temporal behavior, not point-in-time state.

## Conclusion

The control catalog is contradiction-free. The hierarchical guard pattern
(feature-absent → feature-present-but-misconfigured) is used consistently
across 104 field pairs and prevents contradictory findings from appearing
in the same report. No remediation required.
