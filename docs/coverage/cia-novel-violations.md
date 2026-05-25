# CIA Novel Violation Triage (G6)

G6 of Phase 7 takes the CIA findings produced by G4 + G5
(`reasoning/souffle/iam/rules.dl` → `violation_c.csv` / `violation_i.csv`,
then `reasoning/souffle/iam/emit_findings.go` → PostureFindings JSON),
classifies each finding against the existing compound CEL catalog, and
authors new compound CEL controls for the genuinely novel ones.

This document captures **two triage rounds**:

1. **Round 1 — synthetic G4/G5 fixture** (Phase 7 G6 commit
   `dd33e6168`): the first end-to-end pipeline validation.
2. **Round 2 — Shape-B incident fixtures** (Phase 7 candidate B,
   added after closeout): real-shape fixtures drawn from public
   breach analyses, producing the first real-distribution data.

## TL;DR

**First-iteration findings:** 3 CIA violations (1 C + 2 I) against the
synthetic fixture. All 3 classify as **Real novel** in the trivial
sense — the synthetic fixture's pattern (cross-team tag mismatch +
DataClassification=PII bucket) isn't covered by any existing compound
CEL control today, and the auth / sensitivity models are correctly
configured for the fixture.

**Actual backfill DEFERRED** to follow-up iteration. Per the G2
finding (`docs/coverage/iam-datalog-validation.md`), the CIA tier
fires meaningfully only against Shape-B fixtures — observations
that emit `has_action` / `has_resource` sirfacts predicates. The
synthetic fixture used here was hand-built to exercise the
pipeline; it isn't a real production snapshot. Authoring CEL
controls against synthetic-fixture findings would produce templates,
not validated detections.

**The shape of what gets backfilled is documented** as worked-example
YAML snippets below. When real Shape-B fixtures land — operator-
supplied snapshots from production AWS environments where the
extractor's Cognito/Lambda/role-chain mappings populate has_action /
has_resource at scale — the G6 iteration runs against those and the
backfill produces real controls.

**Compound share unchanged:** 180/2658 = 6.77% at G6 entry, same at
G6 exit (no controls shipped because none of the synthetic-finding
backfills are validated detections worth committing).

## Triage classification

For each Datalog-only finding (i.e., violation_c or violation_i rows
with no matching compound CEL predicate), the triage assigns ONE of:

| Category | Meaning | Disposition |
|---|---|---|
| **Real novel** | Access path is genuinely unsafe; no existing CEL control covers it; auth + sensitivity models are correct for this resource | Author new compound CEL control |
| **Authorization model artifact** | `authorized` facts are wrong — the principal IS authorized but the tag-to-group mapping didn't capture it | Fix mapping / resource tags; don't author control |
| **Sensitivity model artifact** | Resource is tagged or framework-mapped as high-sensitivity but shouldn't be | Fix sensitivity classification |
| **Observation gap** | Violation is real but involves asset type / field not in the current observation contract | Route to observation-contract backlog |

## Round 1 — Triage against the G4/G5 synthetic fixture

Source: `/tmp/g45-syn-input.jsonl` — 3 principals × 1 PII bucket.

| # | Finding | Category | Reasoning |
|---|---|---|---|
| 1 | `finance-prod → pii-bucket via s3:GetObject` (Confidentiality) | **Real novel** | finance-prod has Team=Finance; pii-bucket has Team=DataEng + DataClassification=PII. Tag mismatch is unauthorization signal (per G3 model); read action on high-sens resource is the Confidentiality shape. No existing compound CEL covers "cross-team read of DataClassification-PII resource." |
| 2 | `finance-prod → pii-bucket via s3:PutObject` (Integrity) | **Real novel** | Same tag mismatch; write action on high-sens resource is the Integrity shape. Same gap as #1. |
| 3 | `legacy-role → pii-bucket via s3:DeleteObject` (Integrity) | **Real novel** | legacy-role is untagged → fail-closed against tagged pii-bucket. Delete action on high-sens resource. Same gap. |

**Counts:**
- Real novel: 3
- Authorization model artifact: 0
- Sensitivity model artifact: 0
- Observation gap: 0

**Caveat:** the synthetic fixture is purpose-built to exercise the
pipeline end-to-end; the "novel" classification is trivial because no
existing CEL control was designed for this exact synthetic pattern.
The classification's value emerges against real Shape-B fixtures where
the distribution across the four categories carries information
about (a) whether the catalog has gaps worth filling, (b) whether
the auth/sensitivity models are tuned correctly, and (c) what
observation-contract additions would unlock the most novel detection.

## Round 2 — Triage against Shape-B incident fixtures

Sources: hand-authored fixtures at
`reasoning/souffle/iam/fixtures/` modelling two public breach shapes:

1. **`cap-one-pattern.jsonl`** — Capital One 2019: web role with
   broad S3 permissions on a PII-tagged bucket, role untagged
   against the bucket's ownership tag.

2. **`cognito-anon-pattern.jsonl`** — recurring Cognito
   misconfiguration: identity pool admits unauthenticated
   principals, maps them to an IAM role with broad data-plane
   grants, the data-plane resource is PII-tagged. Includes a
   mismatched-tag variant on the authenticated role.

### Round 2 distribution

**Total CIA findings: 9 (7 Confidentiality + 2 Integrity).**

| Fixture | Findings | violation_c | violation_i | unauthorized_access |
|---|---|---|---|---|
| `cap-one-pattern` | 3 | 3 | 0 | 6 |
| `cognito-anon-pattern` | 6 | 4 | 2 | 8 |
| **Total** | **9** | **7** | **2** | **14** |

### Round 2 per-finding triage

| # | Fixture | Finding | Category | Reasoning |
|---|---|---|---|---|
| 1 | cap-one | WAF-Role → customer-credit-card-data via s3:GetObject (C) | **Real novel** | Web role tagged nothing; bucket tagged Team=DataPlatform + DataClassification=PII. WAF-Role's broad s3:Get* permissions reach PII despite ownership boundary. The Capital One pattern exactly. |
| 2 | cap-one | WAF-Role → customer-credit-card-data via s3:GetObjectVersion (C) | **Real novel** | Same as #1; s3:GetObjectVersion is the version-aware read variant. |
| 3 | cap-one | WAF-Role → customer-credit-card-data via s3:ListBucket (C) | **Real novel** | Same as #1; bucket-enumeration is read-action-class. |
| 4 | cognito-anon | CognitoUnauthRole → customer-profiles via dynamodb:GetItem (C) | **Real novel** | Anonymous principal (via Cognito identity pool's `allows_unauthenticated=true`) reaches PII table via mapped role; role is untagged → fail-closed against tagged table. |
| 5 | cognito-anon | CognitoUnauthRole → customer-profiles via dynamodb:Query (C) | **Real novel** | Same anonymous reach via Query action. |
| 6 | cognito-anon | CognitoAuthRole → customer-profiles via dynamodb:GetItem (C) | **Real novel** | Authenticated principal but Team=AppPlatform; PII table is Team=DataPlatform. Cross-team unauthorized read. |
| 7 | cognito-anon | CognitoAuthRole → customer-profiles via dynamodb:Query (C) | **Real novel** | Same cross-team read. |
| 8 | cognito-anon | CognitoAuthRole → customer-profiles via dynamodb:PutItem (I) | **Real novel** | Cross-team write — Integrity violation. |
| 9 | cognito-anon | CognitoAuthRole → customer-profiles via dynamodb:UpdateItem (I) | **Real novel** | Cross-team write via UpdateItem. |

### Round 2 category counts

- **Real novel: 9** — every finding represents an access path no
  existing compound CEL control flags
- **Authorization model artifact: 0**
- **Sensitivity model artifact: 0**
- **Observation gap: 0**

### Round 2 findings — significance

**The Round 2 distribution is informationally meaningful in ways
Round 1's wasn't.** Specifically:

1. **The Capital One shape is detected end-to-end.** A WAF role
   with broad S3 permissions on a PII-tagged bucket fires 3
   Confidentiality findings without any per-control CEL having
   been authored. This is the prototypical "what CSPM should
   catch" example, and the access-graph reachability model catches
   it from the access graph + ownership tags + DataClassification
   tag alone.

2. **The Cognito anonymous shape produces both anonymous-reach
   and cross-team-reach variants in the same fixture.** Findings
   4-5 are the anonymous-reach case (CognitoUnauthRole reaching
   PII); findings 6-7 are the cross-team-reach case
   (CognitoAuthRole tagged Team=AppPlatform reaching
   Team=DataPlatform PII). Both fire because the same auth model
   (tag equality) classifies both as unauthorized. The model
   doesn't need separate logic for "anonymous" vs
   "wrong-team" — both produce unauthorized_access, both compose
   with sensitivity=high and read_action.

3. **Integrity findings fire on real shapes.** The Cognito
   CognitoAuthRole's PutItem and UpdateItem actions on the PII
   table fire violation_i in addition to the Confidentiality reach.
   The dual-firing on `s3:*` style wildcards documented in
   `action_classes.dl` would produce similar overlapping findings;
   here the actions are specific and the integrity findings are
   distinct from the confidentiality ones.

4. **Recurring patterns emerge across fixtures.** The "broad
   data-plane access + cross-team tag mismatch on PII resource"
   shape repeats across both fixtures with different services
   (S3 in Cap One; DynamoDB in Cognito-anon). This is the kind
   of recurring pattern G6 was designed to surface as
   high-priority backfill targets. The backfilled control YAMLs
   (target shapes shown below) would be authored to catch this
   recurrence regardless of which specific service the access
   touches.

5. **No artifact / observation-gap findings.** All 9 findings
   classify as Real novel. The G3 authorization + sensitivity
   models are correctly tuned for these incident shapes; no
   observation-contract gaps surfaced. The model is doing what
   it's supposed to do on real-shape data.

### What Round 2 unlocks for backfill prioritization

The recurring "broad data-plane action + cross-team tag mismatch +
DataClassification=PII" pattern emerges from Round 2 across 2 of
2 fixtures. That's a HIGH-PRIORITY backfill target — a single
compound CEL control authored against that pattern would catch
both shapes (and similar shapes in future fixtures).

The worked-example controls below (originally drafted for the
synthetic fixture) capture this exact pattern. Round 2 confirms
they're the right backfill targets. The remaining gating
constraint is the observation-contract precondition documented
below.

## Worked-example compound CEL control (NOT SHIPPED)

What would the backfill control look like for finding #1? The shape
is one compound CEL control per access-graph pattern, scoped to the
resource asset type (S3 bucket), reading a pre-computed cross-asset
field the extractor would populate.

```yaml
# controls/s3/access/CTL.S3.CIA.UNAUTHORIZED_READ.001.yaml
# WORKED EXAMPLE — not committed to the catalog because the
# observation contract doesn't yet carry the pre-computed
# unauthorized_read_principals_count field. See "Backfill
# precondition" below for the dependency.
dsl_version: ctrl.v1
id: CTL.S3.CIA.UNAUTHORIZED_READ.001
name: S3 Bucket Has Unauthorized Read Reach (CIA Confidentiality)
description: >
  S3 bucket marked DataClassification=high (PII/PHI/PCI) is
  effectively readable by at least one IAM principal whose
  ownership tag (Owner or Team) does not match the bucket's
  ownership tag. Derived intensionally from the Phase 7 access
  graph: violation_c fires on (unauthorized_access × high
  sensitivity × read action).
domain: exposure
severity: critical
scope: compound
corpus_reference: "CIA-derived: tag-mismatched principal has effective read access to DataClassification-tagged resource via access-graph reachability analysis (Phase 7 G4)"
classification: state_assertion
applicable_asset_types:
  - aws_s3_bucket
params:
  attack_stage: exfiltration
observation_fields:
  - storage.access.unauthorized_read_principals_count
  - storage.classification.high_sensitivity
compliance:
  cia_triad: "C"
  hipaa: "164.312(a)(1)"
  pci_dss_v4.0: "7.2.1"
  ccm_v4: ["DSP-13", "IAM-16"]
unsafe_predicate:
  all:
    - field: properties.storage.classification.high_sensitivity
      op: eq
      value: true
    - field: properties.storage.access.unauthorized_read_principals_count
      op: gt
      value: 0
remediation:
  description: >
    Bucket has at least one principal with effective read access
    whose ownership tag (Owner / Team) doesn't match the bucket's
    ownership tag.
  action: >
    Either (a) tag the principal to match the bucket's ownership,
    (b) revoke the principal's effective read permissions via
    IAM policy revision, or (c) re-classify the bucket's
    DataClassification tag if it's incorrectly elevated.
defect: >
  Bucket data is reachable by principals outside the resource's
  ownership boundary.
infection: >
  S3 bucket effective access is computed across direct IAM grants,
  role-assumption chains, group-inherited policies, and resource-
  level policies. When the access graph surfaces a principal who
  can perform a read action AND that principal isn't tagged as a
  member of the bucket's ownership group, the bucket data is
  reachable outside intended boundaries. For DataClassification-
  PII/PHI/PCI buckets, this is a Confidentiality violation —
  irrespective of which specific policy granted the access.
failure: >
  Cross-team or cross-account data exposure via paths the per-
  policy controls don't catch. Auditors reading any single bucket
  policy or IAM policy in isolation see no violation; the access
  graph composition is where the violation lives.
tests:
  - name: unauthorized read reach fires
    verdict: VIOLATION
    asset:
      asset_id: "arn:aws:s3:::prod-pii-bucket"
      asset_type: aws_s3_bucket
      vendor: aws
      properties:
        storage:
          classification:
            high_sensitivity: true
          access:
            unauthorized_read_principals_count: 1
  - name: bucket with no unauthorized reach passes
    verdict: PASS
    asset:
      asset_id: "arn:aws:s3:::prod-pii-bucket"
      asset_type: aws_s3_bucket
      vendor: aws
      properties:
        storage:
          classification:
            high_sensitivity: true
          access:
            unauthorized_read_principals_count: 0
```

Mirror form for Integrity (finding #2 + #3):

```yaml
# controls/s3/access/CTL.S3.CIA.UNAUTHORIZED_WRITE.001.yaml
# WORKED EXAMPLE — same deferral as above.
id: CTL.S3.CIA.UNAUTHORIZED_WRITE.001
name: S3 Bucket Has Unauthorized Write Reach (CIA Integrity)
# ... mirror of above with s3:Put/Delete actions ...
observation_fields:
  - storage.access.unauthorized_write_principals_count
  - storage.classification.high_sensitivity
compliance:
  cia_triad: "I"
unsafe_predicate:
  all:
    - field: properties.storage.classification.high_sensitivity
      op: eq
      value: true
    - field: properties.storage.access.unauthorized_write_principals_count
      op: gt
      value: 0
# ... rest of YAML ...
```

## Backfill precondition (the gating dependency)

The worked-example controls reference observation fields that **do
not exist in the current contract**:

- `properties.storage.access.unauthorized_read_principals_count`
- `properties.storage.access.unauthorized_write_principals_count`
- `properties.storage.classification.high_sensitivity`

Adding these is an extractor iteration: the extractor would need
to (a) compute effective access for every bucket against every IAM
principal, (b) apply the G3 authorization model, (c) sum up
unauthorized principals by action class, (d) project the result
into the snapshot. This is significant work — essentially running
the G0+G1+G3+G4/G5 Soufflé pipeline at extraction time and
projecting the results into per-bucket booleans.

Per the plan's cross-cutting reminder ("Don't expand the
observation contract during authoring iterations"), G6 does NOT
ship the extractor extension. The worked examples above are the
**target shape** of what backfilled CIA-derived compound CEL
controls would look like; the actual shipping awaits either:

1. **Extractor extension** that pre-computes the cross-asset CIA
   fields and projects them into bucket observations (matches the
   Shape-A escalation-pattern convention)
2. **Per-iteration manual fixtures** — author the YAML, ship
   golden fixtures with the pre-computed fields, accept that
   production snapshots don't carry them yet

Option 1 is the structurally consistent answer; it expands the
observation contract in the same shape escalation-pattern
extractors already do. Option 2 ships controls that fire only
on hand-built fixtures, which is the Shape-A pattern of
deferring extractor work until the catalog need is real.

The G2 structural finding remains: the CIA tier is most useful
against Shape-B fixtures (Cognito reachability, principal-chain
S3 paths). Option 1 is the right answer when those Shape-B
fixtures land in volume.

## Recommended next iteration

When operator-supplied Shape-B fixtures are available:

1. Run the full pipeline (extract → G0+G1+G3+G4/G5 → emit_findings)
   against each fixture
2. Triage each finding through this document's classification
3. Distribution analysis: real-novel vs auth-artifact vs
   sensitivity-artifact vs observation-gap counts
4. For real-novel: prioritize the patterns that recur across
   fixtures (high signal); single-occurrence patterns are
   long-tail and likely deserve case-specific manual review
5. Author compound CEL controls for the recurring patterns,
   per the worked-example shape above
6. Update this document with the actual backfill count and the
   compound-share delta

The infrastructure to do all of this is in place after G4/G5 + G6.
The blocking input is real-fixture data, not more engineering.

## Compound-share update

- **Phase 7 entry (per `aws-compound-control-authoring-plan.md`):** 180/2658 = **6.77%**
- **G6 backfill committed:** 0 controls (worked examples not shipped per backfill precondition above)
- **G6 exit:** 180/2658 = **6.77%** (unchanged)

The 9% headline target the plan originally sized against remains
unmet (~70 more compound controls needed). The honest accounting is
that the trajectory to 9% now requires either:
- The extractor extension (Option 1) that lets CIA backfills ship at
  whatever volume real fixtures produce
- Per-service authoring iterations (Phase 1-6 mode) targeting the
  specific service families where compound share lags

Either path is defensible. The G6 outcome documented here doesn't
foreclose either.

## Phase 7 closeout

G0-G6 ship. The access graph is computable, validated, layered with
authorization + sensitivity, projected through C+I queries, and
emitted as PostureFindings. The remaining work — extractor extension
OR Shape-B fixture authoring — sits outside the Phase 7 boundary as
originally scoped.

Phase 7 was the "engine" iteration: build the intensional detection
tier and validate it works end-to-end. Subsequent phases populate
it with real data and propagate its findings into the rest of the
Stave surface (Powerpipe dashboards, MCP tools, comparison-doc
positioning).
