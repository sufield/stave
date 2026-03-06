# Stave CLI — S3 Controls: Implementation Spec

> Consolidated from two independent analyses:
> - **Analysis A:** Pattern extraction from ~32 project prompts (conversation history)
> - **Analysis B:** Empirical inventory from running stave against 36 project snapshots
>
> **Status:** All 5 controls identified below are now **implemented and shipped**.
> ACCESS.003 required an extractor code change (new `has_external_write` computed
> boolean in `policy.go`). The other 4 were pure YAML additions.

---

## How Each Control Identifies Issues in a Snapshot

Each control evaluates observation snapshots (JSON files in `obs.v0.1` format) through a two-stage pipeline:

1. **Extraction** — The S3 extractor (`internal/adapters/input/extract/s3/`) parses raw AWS configuration data (Terraform plan JSON, API responses) and produces canonical observation fields under `properties.storage.*`. Policy analysis functions in `policy.go` compute boolean flags like `has_external_access`, `has_external_write`, `public_access_fully_blocked`, etc.

2. **Evaluation** — The evaluator matches each resource against the control's `unsafe_predicate`. For `unsafe_state` controls, the predicate is a set of field/op/value conditions combined with `all` (AND) or `any` (OR) logic. A finding fires when every condition in an `all` block is true.

### Detection patterns by control category:

| Category | Detection Method | Example |
|----------|-----------------|---------|
| **PUBLIC.*** | Checks `visibility.*` booleans computed from policy principal analysis + ACL grants | `public_read == true` means Principal:* + GetObject action exists |
| **ENCRYPT.*** | Checks `encryption.*` fields from bucket SSE config | `at_rest_enabled == false` means no SSE-S3 or SSE-KMS configured |
| **ACCESS.*** | Checks `access.*` booleans computed from policy cross-account analysis | `has_external_write == true` means external IAM ARN + write/delete action |
| **CONTROLS.001** | Checks `controls.public_access_fully_blocked` from PAB config | `false` means safety net against accidental public exposure is off |
| **GOVERNANCE.001** | Checks tag presence via `missing` operator | Missing `data-classification` tag means tag-conditional controls silently pass |
| **NETWORK.001** | Checks `policy.effective_network_scope` computed from condition key analysis | `"public"` means Principal:* statements lack IP/VPC/Org conditions |
| **LIFECYCLE/LOCK.*** | Tag-gated: only evaluates buckets with specific classification tags | `data-classification: phi` + `retention_days < 2555` |

### ACCESS.003 — detailed detection flow:

```
Snapshot JSON → resources[].properties.storage.access.has_external_write
                                    ↑
                        Computed by AnalyzeCrossAccountAccess() in policy.go:

For each Allow statement in bucket policy:
  1. Extract Principal ARNs (skip Principal: "*")
  2. Match against arn:aws:iam::<account_id>: pattern
  3. If external account found → check Actions:
     - Exact: s3:PutObject, s3:DeleteObject, s3:PutBucketPolicy,
              s3:DeleteBucket, s3:PutObjectAcl, s3:PutBucketAcl
     - Wildcards: s3:*, *, s3:Put*, s3:Delete*
  4. If any write/delete action found → has_external_write = true

Control predicate: storage.kind == "bucket" AND has_external_write == true
```

---

## Control 1: CTL.S3.CONTROLS.001 — Public Access Block Disabled **[IMPLEMENTED]**

**Priority:** P0 — highest impact, simplest implementation

**Both analyses agree:** This is the #1 gap. Every bare bucket across all 36
projects has `public_access_fully_blocked: false`. No control catches the
*enabling condition* for public exposure — only the *result* (PUBLIC.001
fires after the bucket is already public). This control catches buckets
that are one policy change away from becoming public.

**Observation field:** `properties.storage.controls.public_access_fully_blocked`
— already exists in the canonical model, already populated by the extractor.

**Real-world trigger:** TinaCMS intentionally disables PAB. Discourse's
official setup guide disables 2 of 4 controls. Strapi requires disabled PAB
because `@strapi/provider-upload-aws-s3` uses `s3:PutObjectAcl`. Immich
homelabs disable PAB during FUSE mount debugging and forget to re-enable.
Ghost's community storage adapter doesn't set PAB.

**Why it matters beyond PUBLIC.001:** A bucket with PAB disabled and no
public policy/ACL today will NOT trigger PUBLIC.001. But any future
misconfiguration (accidental public policy, ACL grant to AllUsers) will
take immediate effect with no safety net. This is a latent vulnerability
detector.

```yaml
dsl_version: ctrl.v1
id: CTL.S3.CONTROLS.001
name: Public Access Block Must Be Enabled
description: >
  S3 buckets must have the public access block fully enabled.
  When disabled, the bucket has no safety net against accidental
  public exposure from policy or ACL changes. This detects the
  enabling condition for public access, not the exposure itself.
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.controls.public_access_fully_blocked
      op: eq
      value: false
```

**Expected results across 36 projects:**
- Every bare bucket (36 total) triggers — PAB is disabled by default
  in all test fixtures
- Every mid-tier and enterprise bucket passes — PAB enabled
- TinaCMS bare bucket triggers with the INTENTIONAL public access
  pattern, making it the strongest finding (PAB disabled + public ACL +
  public policy simultaneously)

**Effort:** ~30 minutes. Pure YAML, no code changes. Field already exists.

---

## Control 2: CTL.S3.GOVERNANCE.001 — Data Classification Tag Required **[IMPLEMENTED]**

**Priority:** P0 — gates effectiveness of 6 existing tag-conditional controls

**Both analyses agree:** This is the meta-control problem. Six existing
controls depend on tags to fire: PUBLIC.002 (PHI/PII public), ENCRYPT.003
(PHI without KMS), VERSION.002 (backup without MFA delete), LIFECYCLE.001-002
(retention), LOCK.001-003 (object lock). If a bucket has no
`data-classification` tag, ALL of these controls silently pass — even if
the bucket stores PHI, PII, or confidential data.

**Observation field:** `properties.storage.tags` — already exists. Requires
a predicate operator that can check for tag key absence.

**Real-world trigger:** Every single project in both analyses deploys S3
buckets without data classification tags by default. Paperless-ngx stores
scanned tax returns, Immich stores face-recognition embeddings, KeyDB
stores session tokens — none tagged. The tag-conditional control subsystem
is inert against every real-world deployment in the test suite.

**Implementation note:** This requires checking that a tag key DOES NOT
EXIST. The predicate DSL needs one of:
- `op: missing` (tag key absent)
- `op: not_exists` 
- `op: eq` with `value: ""` if absent tags resolve to empty string

Check which operator the predicate evaluator supports for absent fields.
If the healthcare prompts (LIFECYCLE.001-002) introduced an `exists`
operator, the inverse should be available or trivially added.

```yaml
dsl_version: ctrl.v1
id: CTL.S3.GOVERNANCE.001
name: Data Classification Tag Required
description: >
  S3 buckets must have a data-classification tag. Without this tag,
  tag-conditional controls for PHI, PII, confidential data, backup
  integrity, and compliance retention cannot evaluate — the bucket
  silently passes all sensitivity-gated checks regardless of actual
  content.
domain: governance
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.tags.data-classification
      op: missing
      value: true
```

**Expected results across 36 projects:**
- Every bare bucket triggers (none are tagged)
- Mid-tier buckets: depends on fixture — most are tagged
  `data-classification: internal` or `confidential`
- Enterprise buckets: all tagged, all pass

**Effort:** 30 minutes if `missing`/`not_exists` operator exists. 2-4 hours
if a new predicate operator must be added to `unsafe_predicate_eval.go`.

---

## Control 3: CTL.S3.ENCRYPT.004 — Confidential Data Requires KMS **[IMPLEMENTED]**

**Priority:** P1 — extends ENCRYPT.003 coverage beyond PHI

**Both analyses agree:** ENCRYPT.003 only fires on `data-classification: phi`.
But enterprise-secure buckets across the test suite are tagged
`data-classification: confidential` or `data-classification: internal` and
use SSE-KMS — yet no control ENFORCES this for non-PHI sensitive data.
A bucket tagged `confidential` using AES256 (SSE-S3) passes all existing
controls, even though the organization's policy likely requires
customer-managed keys for confidential data.

**Observation fields:** `properties.storage.encryption.algorithm` and
`properties.storage.tags.data-classification` — both already exist.

**Real-world trigger:** ClickHouse analytics buckets tagged `confidential`
with user emails, IP addresses, financial transactions. Airflow log buckets
tagged `internal` containing pipeline credentials in XCom. Sentry debug
symbols tagged `internal` containing complete application source code.
All using AES256 instead of KMS.

```yaml
dsl_version: ctrl.v1
id: CTL.S3.ENCRYPT.004
name: Confidential and Internal Data Requires KMS Encryption
description: >
  S3 buckets tagged data-classification as confidential or internal
  must use SSE-KMS encryption with a customer-managed key, not SSE-S3
  (AES256). AES256 uses AWS-managed keys with no customer control over
  key rotation, access policies, or audit trails.
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.tags.data-classification
      op: in
      value: ["confidential", "internal"]
    - field: properties.storage.encryption.algorithm
      op: ne
      value: "aws:kms"
```

**Expected results across 36 projects:**
- Bare buckets: only triggers if tagged (most aren't — GOVERNANCE.001
  catches the missing tag). The ones that ARE tagged `confidential` with
  no encryption will trigger ENCRYPT.001 first (no encryption at all),
  making this control fire on the MID-TIER buckets that have AES256
  but not KMS.
- Mid-tier buckets tagged `confidential` + AES256: triggers
- Enterprise buckets with KMS: passes

**Requires:** `in` operator (check if tag value is in a list) and `ne`
(not equal). Verify both exist in `unsafe_predicate_eval.go`. If `ne` doesn't
exist, use the equivalent:

```yaml
# Alternative without `ne`:
unsafe_predicate:
  all:
    - field: properties.storage.tags.data-classification
      op: in
      value: ["confidential", "internal"]
    - field: properties.storage.encryption.algorithm
      op: eq
      value: "AES256"
```

This alternative fires when algorithm IS AES256 (rather than when it's
NOT aws:kms), which is equivalent for the two-value enum but less
future-proof if new algorithms appear.

**Effort:** 30 minutes if `in` and `ne` operators exist. 2-4 hours if
either must be added.

---

## Control 4: CTL.S3.PUBLIC.006 — Latent Public List Exposure **[IMPLEMENTED]**

**Priority:** P1 — completes the latent exposure detection pair

**Analysis B surfaced this; Analysis A missed it.** The observation schema
tracks both `latent_public_read` and `latent_public_list`. PUBLIC.005
already covers `latent_public_read`. No control covers `latent_public_list`.
This is an asymmetry in the existing coverage — the field exists, is
populated, and has no check.

**Observation field:** `properties.storage.visibility.latent_public_list`
— already exists and populated.

**What "latent" means:** The bucket has a policy or ACL that would grant
public listing, but PAB is currently blocking it. If PAB is ever disabled
(CONTROLS.001 fires), the listing exposure activates immediately. This
is the second-order risk: CONTROLS.001 catches PAB-off, PUBLIC.006 catches
"PAB-off would expose listing."

**Real-world trigger:** Mastodon buckets where public object read is
intentional but bucket listing must be denied — if PAB is removed AND
a ListBucket policy exists, all object keys become enumerable. Gitea
with mixed public/private packages where listing reveals private package
names. ClickHouse shared datasets where listing exposes private dataset
keys mixed in the same bucket.

```yaml
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.006
name: Latent Public Bucket Listing
description: >
  S3 bucket has a policy or ACL that would allow public listing
  if the public access block were removed. The public access block
  is currently the only control preventing directory enumeration.
  This is a latent vulnerability — one configuration change away
  from exposing all object keys.
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.visibility.latent_public_list
      op: eq
      value: true
```

**Expected results:** Fires on any bucket where PAB is the sole barrier
to public listing. Complementary to PUBLIC.005 (latent read).

**Effort:** ~30 minutes. Pure YAML. Field already exists and is populated.

---

## Control 5: CTL.S3.ACCESS.003 — External Write Access **[IMPLEMENTED]**

**Priority:** P2 — required extractor code change (now complete)

**Both analyses identified this gap, framed differently.** Analysis A
focused on admin-level actions (`s3:PutBucketPolicy` as privilege
escalation). Analysis B focused on the read-vs-write distinction for
cross-account access. The common ground: ACCESS.001 fires on ANY
external access, but a read-only analytics partner is categorically
less dangerous than a contractor with `s3:PutObject` + `s3:DeleteObject`.

**The implementation question:** The observation schema captures full
`policy_json` in vendor evidence, which contains the Actions. But the
`unsafe_state` predicate DSL operates on flattened canonical fields, not
on nested JSON arrays within policy documents. Two paths:

**Implementation (Path A — new canonical field):**
Added `properties.storage.access.has_external_write` as a boolean computed
during extraction, alongside the existing `has_external_access`. The
extractor parses policy statements, identifies external account ARNs,
then checks whether the Actions in those statements include write/delete
operations.

**Code changes:**
- `policy.go`: Added `HasExternalWrite bool` to `CrossAccountAnalysis` struct.
  Added `isWriteAction()` helper that detects write/delete patterns:
  `s3:PutObject`, `s3:DeleteObject`, `s3:PutBucketPolicy`, `s3:DeleteBucket`,
  `s3:PutObjectAcl`, `s3:PutBucketAcl`, and wildcards (`s3:*`, `*`,
  `s3:Put*`, `s3:Delete*`). Modified `AnalyzeCrossAccountAccess()` to
  call `isWriteAction()` on actions from external-principal Allow statements.
- `extractor.go`: Added `has_external_write` to the `access` map in the
  canonical model.
- `policy_test.go`: 5 new tests — read-only (false), write (true),
  wildcard (true), no external (false), Put* prefix (true).

```yaml
dsl_version: ctrl.v1
id: CTL.S3.ACCESS.003
name: No External Write Access
description: >
  S3 buckets must not grant write or delete permissions to external
  AWS accounts. Cross-account read access may be acceptable for
  analytics or auditing, but write access from external accounts
  creates data integrity and supply chain risks.
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.has_external_write
      op: eq
      value: true
```

**How it identifies issues in a snapshot:**
The control fires when a bucket's policy grants write or delete
permissions to an AWS account outside the organization. The detection
pipeline works in two stages:

1. **Extraction** (`AnalyzeCrossAccountAccess` in `policy.go`): For each
   Allow statement in the bucket policy, extract principal ARNs. If any
   match the `arn:aws:iam::<account_id>:` pattern (external accounts),
   check the statement's Actions. If any action matches a write/delete
   pattern (exact match like `s3:PutObject`, or prefix like `s3:Put*`,
   or full wildcard `s3:*`/`*`), set `has_external_write = true`.

2. **Evaluation**: The predicate checks `storage.kind == bucket` AND
   `storage.access.has_external_write == true`. Both must be true for
   the finding to fire.

**Real-world verification results:**
- TinaCMS `agency-cms-media`: ACCESS.001 + ACCESS.003 both fire
  (freelancer has `s3:PutObject` + `s3:GetObject` + `s3:ListBucket`)
- golang-migrate `shared-migrations-repo`: ACCESS.001 + ACCESS.003 both fire
  (DBA contractor has `s3:GetObject` + `s3:PutObject` + `s3:ListBucket`)
- Airflow `company-airflow-data`: ACCESS.001 fires but ACCESS.003 does NOT
  (analytics vendor has only `s3:GetObject` + `s3:ListBucket` — read-only)
- Enterprise-secure buckets: neither ACCESS.001 nor ACCESS.003 fires
  (no external account access at all)

---

## Summary

| # | ID | Name | Priority | Status | Code Changes |
|---|-----|------|----------|--------|-------------|
| 1 | CONTROLS.001 | PAB Disabled | P0 | **Shipped** | YAML only |
| 2 | GOVERNANCE.001 | Missing Classification Tag | P0 | **Shipped** | YAML only (`missing` operator existed) |
| 3 | ENCRYPT.004 | Confidential Without KMS | P1 | **Shipped** | YAML only (`in` and `ne` operators existed) |
| 4 | PUBLIC.006 | Latent Public List | P1 | **Shipped** | YAML only |
| 5 | ACCESS.003 | External Write Access | P2 | **Shipped** | Extractor change: `policy.go` + `extractor.go` + tests |

All 5 controls are implemented and verified against the 36-project
snapshot test suite. ACCESS.003 required adding `has_external_write` as
a computed boolean in the S3 policy analysis pipeline (`policy.go`),
exposing it in the canonical model (`extractor.go`), and updating
snapshot observation files to include the new field.

---

## Excluded from This Spec

These gaps were identified in one or both analyses but are NOT
implementable with the current observation schema and predicate DSL:

| Gap | Why Excluded |
|-----|-------------|
| Event notification detection | Requires extracting `aws_s3_bucket_notification` — new Terraform resource |
| Explicit delete denial (DENY policies) | Requires policy DENY effect analysis — current extractor only surfaces ALLOW effects for access computation |
| ACL legacy re-enablement | Observable (TinaCMS triggers it) but no distinct canonical field for "ACLs are actively used" vs "ACLs are disabled" |
| Mixed data sensitivity in single bucket | Not detectable from bucket configuration — requires application architecture knowledge |
| CORS misconfiguration | Not captured in current observation schema |
| Cross-account write vs. admin actions | Partially addressed by ACCESS.003 above; full action-level parsing (distinguishing `s3:PutBucketPolicy` from `s3:PutObject`) requires deeper policy decomposition |
| Cross-environment aggregation | Requires understanding environment topology beyond bucket config |
| Multi-tenant path isolation | Requires understanding tenant model beyond bucket config |

These belong in a future roadmap, not the current implementation cycle.

---

# S3 Control Inventory & Gap Analysis

## 36 Open-Source Projects Analyzed

Each project uses S3 in a distinct way. All share the same 3-bucket test fixture pattern: a bare bucket (no hardening), a mid-tier bucket (AES256 + cross-account access), and an enterprise-secure bucket (SSE-KMS, versioning+MFA, logging, deny policies).

| # | Project | S3 Role | s3/ | all | Warns |
|---|---------|---------|-----|-----|-------|
| 1 | Strapi | CMS media uploads | 7 | 7 | 25 |
| 2 | Immich | Photo/video backup storage | 8 | 8 | 25 |
| 3 | Mastodon | Federated media attachments | 9 | 13 | 24 |
| 4 | Rclone | Cloud sync target | 10 | 12 | 25 |
| 5 | Terraform | Remote state backend | 8 | 8 | 25 |
| 6 | Gitea | Git LFS / repo objects | 9 | 12 | 25 |
| 7 | Discourse | Forum uploads / backups | 9 | 10 | 25 |
| 8 | Spark | Data lake parquet files | 8 | 8 | 25 |
| 9 | Sentry | Error attachments / debug symbols | 9 | 11 | 25 |
| 10 | Airflow | DAG storage / logs | 9 | 9 | 25 |
| 11 | ClickHouse | Analytics cold storage | 9 | 12 | 25 |
| 12 | Nextcloud | Personal cloud storage | 9 | 9 | 25 |
| 13 | Restic | Encrypted backup repository | 11 | 11 | 25 |
| 14 | Loki | Log chunk storage | 9 | 9 | 25 |
| 15 | Harbor | Container image layers | 9 | 9 | 25 |
| 16 | Paperless | Document archive | 9 | 9 | 25 |
| 17 | GitLab | CI artifacts / LFS | 9 | 9 | 25 |
| 18 | MLflow | ML model artifacts | 9 | 9 | 25 |
| 19 | DVC | ML dataset versioning | 9 | 9 | 25 |
| 20 | Thanos | Prometheus metrics long-term | 9 | 9 | 25 |
| 21 | KeyDB | RDB/AOF snapshot persistence | 9 | 9 | 25 |
| 22 | Dagster | Pipeline asset storage | 9 | 9 | 25 |
| 23 | Litestream | SQLite WAL replication | 9 | 9 | 25 |
| 24 | JuiceFS | Distributed filesystem backend | 9 | 9 | 25 |
| 25 | Velero | Kubernetes cluster backups | 9 | 9 | 25 |
| 26 | Presto | Query result staging | 9 | 9 | 25 |
| 27 | s3fs | FUSE-mounted filesystem | 9 | 9 | 25 |
| 28 | Directus | Headless CMS assets | 9 | 9 | 25 |
| 29 | Ghost | Blog media + themes | 9 | 11 | 25 |
| 30 | Payload | CMS uploads / media | 9 | 9 | 25 |
| 31 | Iceberg | Table format metadata + data | 9 | 9 | 25 |
| 32 | Serverless | Deployment artifacts | 9 | 9 | 25 |
| 33 | golang-migrate | Database migration SQL files | 9 | 9 | 25 |
| 34 | Open SaaS | SaaS template user uploads | 9 | 9 | 25 |
| 35 | SiYuan | Personal knowledge sync | 9 | 9 | 25 |
| 36 | TinaCMS | CMS media (PUBLIC buckets) | 11 | 15 | 24 |

**Key observations:**
- **30 of 36 projects** produce the standard pattern: s3/=9, all=9, 25 warnings
- **6 outliers** have elevated violation counts due to public access flags or additional exposure vectors
- **TinaCMS** is the most violated (15 findings) — it's the only project with intentionally public buckets (PAB disabled, AllUsers READ ACL)

---

## S3 Control Inventory (27 files, ~24 unique checks)

There are **28 YAML files** across 3 directories. Two IDs are duplicated with different types:

### Directory 1: `controls/` (root — 2 files)

| ID | Name | Type | Checks |
|----|------|------|--------|
| CTL.S3.PUBLIC.001 | No Public S3 Buckets | unsafe_state | `public_read == true` OR `public_list == true` |
| CTL.S3.PUBLIC.002 | No Public Buckets With Sensitive Data | unsafe_state | public read/list + tags (phi/pii/confidential) |

### Directory 2: `controls/s3/` (21 files)

| ID | Name | Type | Checks |
|----|------|------|--------|
| CTL.S3.PUBLIC.003 | No Public Write | unsafe_state | `public_write == true` |
| CTL.S3.PUBLIC.006 | Latent Public Bucket Listing | unsafe_state | `latent_public_list == true` |
| CTL.S3.ENCRYPT.001 | Encryption at Rest | unsafe_state | `at_rest_enabled == false` |
| CTL.S3.ENCRYPT.002 | Encryption in Transit | unsafe_state | `in_transit_enforced == false` |
| CTL.S3.ENCRYPT.003 | PHI Requires KMS | unsafe_state | PHI tag + algorithm not `aws:kms` |
| CTL.S3.ENCRYPT.004 | Confidential/Internal Requires KMS | unsafe_state | confidential/internal tag + algorithm not `aws:kms` |
| CTL.S3.VERSION.001 | Versioning Enabled | unsafe_state | `versioning.enabled == false` |
| CTL.S3.VERSION.002 | MFA Delete for Backups | unsafe_state | backup tag + `mfa_delete_enabled == false` |
| CTL.S3.LOG.001 | Logging Enabled | unsafe_state | `logging.enabled == false` |
| CTL.S3.ACCESS.001 | External Account Access | unsafe_state | `has_external_access == true` |
| CTL.S3.ACCESS.002 | Wildcard Policy | unsafe_state | `has_wildcard_policy == true` |
| CTL.S3.ACCESS.003 | No External Write Access | unsafe_state | `has_external_write == true` (external accounts with write/delete actions) |
| CTL.S3.CONTROLS.001 | Public Access Block Must Be Enabled | unsafe_state | `public_access_fully_blocked == false` |
| CTL.S3.GOVERNANCE.001 | Data Classification Tag Required | unsafe_state | `tags.data-classification` missing |
| CTL.S3.PUBLIC.PREFIX.001 | Protected Prefixes Must Not Be Publicly Readable | prefix_exposure | Protected prefixes publicly readable via policy/ACL |
| CTL.S3.NETWORK.001 | Network Scope | unsafe_state | `effective_network_scope == "public"` |
| CTL.S3.LIFECYCLE.001 | Lifecycle for Retention Data | unsafe_state | data-retention tag + `rules_configured == false` |
| CTL.S3.LIFECYCLE.002 | PHI Minimum Retention | unsafe_state | PHI tag + `min_expiration_days < 2190` |
| CTL.S3.LOCK.001 | Object Lock for Compliance | unsafe_state | compliance tag + `object_lock.enabled == false` |
| CTL.S3.LOCK.002 | Lock Mode COMPLIANCE | unsafe_state | compliance tag + `mode != COMPLIANCE` |
| CTL.S3.LOCK.003 | Lock Retention Period | unsafe_state | PHI tag + `retention_days < 2555` |

### Directory 3: `controls/storage/object_storage/s3/` (5 files)

| ID | Name | Type | Checks |
|----|------|------|--------|
| CTL.S3.PUBLIC.001 | No Public Read via Policy | unsafe_duration | `public_read_via_policy == true` (0h tolerance) |
| CTL.S3.PUBLIC.002 | No Public List via Policy | unsafe_duration | `public_list_via_policy == true` (0h tolerance) |
| CTL.S3.PUBLIC.004 | No Public Read via ACL | unsafe_duration | `public_read_via_acl == true` (0h tolerance) |
| CTL.S3.PUBLIC.005 | Latent Public Read | unsafe_state | `latent_public_read == true` |
| CTL.S3.INCOMPLETE.001 | Safety Provable | unsafe_duration | `safety_provable == false` |

**Note:** CTL.S3.PUBLIC.001 and CTL.S3.PUBLIC.002 each have TWO definitions — one `unsafe_state` (root) and one `unsafe_duration` (storage/). When both directories are merged for evaluation, both fire independently.

---

## Previously Missing Controls — Now Implemented

Based on the 36 projects, these security patterns were identified as gaps.
**All 5 are now implemented** (see Directory 2 above):

### 1. Public Access Block (PAB) Enforcement — **IMPLEMENTED as CONTROLS.001**

CONTROLS.001 checks whether PAB is disabled:
```yaml
field: properties.storage.controls.public_access_fully_blocked
op: eq
value: false   # → violation
```
This catches the *enabling condition* — a bucket one policy change away from
becoming public — rather than detecting public buckets after the fact.

**Affected projects:** All 36 (every bare bucket has PAB=false), but especially TinaCMS where PAB is intentionally disabled.

### 2. Cross-Account Write vs. Read Distinction — **IMPLEMENTED as ACCESS.003**

ACCESS.001 fires on `has_external_access == true` but treats all external access equally. ACCESS.003 now distinguishes:
- **Read-only external** (analytics partner in Airflow) — ACCESS.001 fires, ACCESS.003 does NOT
- **Write external** (DBA contractor in golang-migrate with PutObject, freelancer in TinaCMS with PutObject+DeleteObject) — both ACCESS.001 and ACCESS.003 fire

Implementation: Added `has_external_write` computed boolean to the S3 policy
analysis pipeline. The extractor checks actions on external-principal Allow
statements for write/delete patterns (`s3:PutObject`, `s3:DeleteObject`,
`s3:PutBucketPolicy`, `s3:DeleteBucket`, `s3:PutObjectAcl`, `s3:PutBucketAcl`,
and wildcards `s3:*`, `*`, `s3:Put*`, `s3:Delete*`). No `prefix_exposure`
evaluator was needed — a new canonical field was sufficient.

### 3. Confidential/Restricted Data Without KMS — **IMPLEMENTED as ENCRYPT.004**

ENCRYPT.003 only triggers on `data-classification: phi`. ENCRYPT.004 now
extends coverage to `data-classification: confidential` and `internal`,
enforcing KMS over AES256 for all sensitive data classifications.

### 4. Tag Presence Requirement — **IMPLEMENTED as GOVERNANCE.001**

GOVERNANCE.001 enforces that buckets *have* a `data-classification` tag.
Without this tag, tag-conditional controls (PHI, compliance, backup)
silently pass — the entire tag-conditional subsystem was inert against
untagged buckets. Uses the `missing` predicate operator.

### 5. Latent Public Exposure — **IMPLEMENTED as PUBLIC.006**

PUBLIC.005 checks `latent_public_read`. PUBLIC.006 now covers
`latent_public_list` — catching buckets where PAB is the only thing
preventing directory listing.

### 6. ACL Legacy Re-enablement — LOW

TinaCMS re-enables ACLs (AWS legacy feature) to grant AllUsers READ. No control detects "ACLs are actively being used" vs "ACLs are disabled (modern default)." The `public_read_via_acl` flag in the observation catches the public case, but a bucket could have ACL grants to specific accounts without triggering any control.

### 7. Patterns That Can't Be Expressed as Bucket-Level Controls

These were documented across projects but **cannot be implemented** with the current observation schema (they'd require new observation types or enrichment):

| Pattern | Projects | Why Not Expressible |
|---------|----------|-------------------|
| Template propagation risk | Open SaaS | Security flaws in templates multiply — this is a supply chain property, not a bucket property |
| Executable content in S3 | golang-migrate | SQL migration files ARE executable code — bucket metadata doesn't describe object content types |
| Optional E2E encryption bypass | SiYuan | Client-side encryption is an app-layer concern outside bucket configuration |
| Filename intelligence | golang-migrate, s3fs | Object key patterns reveal database schemas — requires object-level scanning |
| Documentation-driven insecurity | Open SaaS | "Leave all settings as default" in docs — requires content analysis |
| CORS misconfiguration | Open SaaS, TinaCMS | Not captured in current observation schema |
| Presigned URL patterns | Multiple | Runtime behavior, not bucket configuration |

---

## Coverage Heatmap

| Observation Field | Control Coverage | Gap |
|-------------------|-------------------|-----|
| `visibility.public_read` | PUBLIC.001 (state + duration) | Covered |
| `visibility.public_list` | PUBLIC.001 (state), PUBLIC.002 (duration) | Covered |
| `visibility.public_write` | PUBLIC.003 | Covered |
| `visibility.public_read_via_policy` | PUBLIC.001 (duration) | Covered |
| `visibility.public_read_via_acl` | PUBLIC.004 (duration) | Covered |
| `visibility.public_list_via_policy` | PUBLIC.002 (duration) | Covered |
| `visibility.latent_public_read` | PUBLIC.005 | Covered |
| `visibility.latent_public_list` | PUBLIC.006 | Covered |
| `controls.public_access_fully_blocked` | CONTROLS.001 | Covered |
| `controls.public_access_block.*` | **NONE** | **Gap** (individual PAB controls not checked) |
| `encryption.at_rest_enabled` | ENCRYPT.001 | Covered |
| `encryption.in_transit_enforced` | ENCRYPT.002 | Covered |
| `encryption.algorithm` | ENCRYPT.003 (PHI), ENCRYPT.004 (confidential/internal) | Covered |
| `versioning.enabled` | VERSION.001 | Covered |
| `versioning.mfa_delete_enabled` | VERSION.002 (backup tag only) | **Partial** — not for compliance/soc2 |
| `logging.enabled` | LOG.001 | Covered |
| `access.has_external_access` | ACCESS.001 | Covered |
| `access.has_external_write` | ACCESS.003 | Covered (distinguishes write/delete from read-only) |
| `access.has_wildcard_policy` | ACCESS.002 | Covered |
| `policy.effective_network_scope` | NETWORK.001 | Covered |
| `policy.has_ip_condition` | **NONE** | **Gap** (could enforce VPC/IP restrictions) |
| `policy.has_vpc_condition` | **NONE** | **Gap** |
| `lifecycle.*` | LIFECYCLE.001-002 (tag-gated) | Covered for tagged buckets |
| `object_lock.*` | LOCK.001-003 (tag-gated) | Covered for tagged buckets |
| `tags.data-classification` existence | GOVERNANCE.001 | Covered |

---

## Previously Recommended Controls — All Shipped

All 5 recommended controls are now implemented:

1. **CTL.S3.CONTROLS.001** — PAB disabled detection — **Shipped** (YAML only)
2. **CTL.S3.GOVERNANCE.001** — Missing data-classification tag — **Shipped** (YAML only, `missing` operator)
3. **CTL.S3.ENCRYPT.004** — Confidential/internal data without KMS — **Shipped** (YAML only, `in` + `ne` operators)
4. **CTL.S3.PUBLIC.006** — Latent public list exposure — **Shipped** (YAML only)
5. **CTL.S3.ACCESS.003** — External write access — **Shipped** (extractor change: `has_external_write` computed boolean)

---

# Stave CLI — Controls Surfaced by Open-Source Project Analysis

> Based on analysis of ~32 prompts covering 95 test buckets across the top-25
> OSS projects plus additional projects (KeyDB, Ghost, Directus, Serverless
> Framework, etc.)
>
> **Status:** All controls from this analysis that are expressible with the
> current DSL and observation schema have been implemented.

---

## Current Control Inventory

### Shipped / Implemented

| ID | Name | What It Catches |
|----|------|-----------------|
| CTL.S3.PUBLIC.001 | No Public S3 Buckets | `public_read` or `public_list` via policy/ACL |
| CTL.S3.PUBLIC.002 | No Public PHI Buckets | Public + `data-classification=phi` tag combo |
| CTL.S3.PUBLIC.003 | No Public Write Access | `public_write` via policy/ACL |
| CTL.S3.PUBLIC.006 | Latent Public Bucket Listing | PAB is only barrier to public listing |
| CTL.S3.ACCOUNT.001 | Account-Level Public Access Block | Account-level PAB not fully enabled |
| CTL.S3.CONTROLS.001 | Public Access Block Must Be Enabled | Bucket-level PAB disabled (latent exposure) |
| CTL.S3.ENCRYPT.001 | Encryption at Rest Required | No SSE configured |
| CTL.S3.ENCRYPT.002 | Transport Encryption Required | No `aws:SecureTransport=false` deny policy |
| CTL.S3.ENCRYPT.004 | Confidential/Internal Requires KMS | Confidential/internal data using AES256 instead of KMS |
| CTL.S3.VERSION.001 | Versioning Required | Versioning not enabled |
| CTL.S3.LOG.001 | Access Logging Required | No server access logging |
| CTL.S3.ACCESS.001 | Cross-Account Access Detection | External account ARNs in policy |
| CTL.S3.ACCESS.002 | Wildcard Policy Detection | `s3:*` action in any policy statement |
| CTL.S3.ACCESS.003 | No External Write Access | External accounts with write/delete actions in policy |
| CTL.S3.GOVERNANCE.001 | Data Classification Tag Required | Missing `data-classification` tag (gates tag-conditional controls) |

### Designed (in prompts / healthcare expansion) — All Shipped

| ID | Name | Source | Status |
|----|------|--------|--------|
| CTL.S3.ENCRYPT.003 | PHI Must Use SSE-KMS with CMK | Gap prompt #1 | Shipped |
| CTL.S3.ENCRYPT.004 | Confidential/Internal Requires KMS | Inventory analysis | Shipped |
| CTL.S3.VERSION.002 | MFA Delete for Backup Buckets | Gap prompt #2 | Shipped |
| CTL.S3.LIFECYCLE.001 | Data Retention Policy Required | Healthcare prompt #5 | Shipped |
| CTL.S3.LIFECYCLE.002 | Minimum Retention Period (2190 days) | Healthcare prompt #5 | Shipped |
| CTL.S3.LOCK.001 | Object Lock Required (compliance-tagged) | Healthcare prompt #6 | Shipped |
| CTL.S3.LOCK.002 | COMPLIANCE Mode for PHI | Healthcare prompt #6 | Shipped |
| CTL.S3.LOCK.003 | Minimum WORM Retention | Healthcare prompt #6 | Shipped |
| CTL.S3.NETWORK.001 | Network-Scoped Policies | Gap prompt #4 | Shipped |
| CTL.S3.CONTROLS.001 | Public Access Block Must Be Enabled | Inventory analysis | Shipped |
| CTL.S3.GOVERNANCE.001 | Data Classification Tag Required | Inventory analysis | Shipped |
| CTL.S3.PUBLIC.006 | Latent Public Bucket Listing | Inventory analysis | Shipped |
| CTL.S3.ACCESS.003 | No External Write Access | Inventory analysis | Shipped (extractor change) |

### Originally Identified (CSA gap analysis) — P2/P3 Priority

| ID | Name | Priority |
|----|------|----------|
| CTL.S3.CORS.001 | No Wildcard CORS Origin | P2 |
| CTL.S3.REPLICATE.001 | Replication to Unapproved Accounts/Regions | P2 |

---

## Additional Control Patterns Surfaced by the 40-Project Analysis

These are patterns that appeared repeatedly across real-world OSS
deployments. Items 1-5 overlap with the 5 implemented controls above.
Items 6-8 remain as future candidates.

---

### 1. CTL.S3.PAB.BUCKET.001 — All Four Bucket-Level Public Access Block Controls Enabled

**Pattern source:** Discourse (split PAB: `block_public_acls=false`,
`ignore_public_acls=false`, but `block_public_policy=true`,
`restrict_public_buckets=true`). First snapshot with partially-enabled PAB.

**Gap:** `CTL.S3.ACCOUNT.001` checks account-level. `CTL.S3.PUBLIC.001`
checks effective public access. But neither checks whether ALL FOUR
bucket-level PAB controls are enabled. A bucket can have no public access
today (because no public policy/ACL exists yet) but have PAB partially
disabled — meaning a future misconfiguration won't be caught by the
safety net.

**Why it matters:** Discourse's official setup guide tells admins to
disable 2 of 4 controls. The bucket isn't public NOW, but the safety net
has a hole. This is a LATENT vulnerability, not an active exposure.

```yaml
id: CTL.S3.PAB.BUCKET.001
name: Bucket-Level Public Access Block Must Be Fully Enabled
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.controls.block_public_acls
      op: eq
      value: false
    - field: properties.storage.controls.ignore_public_acls
      op: eq
      value: false
    - field: properties.storage.controls.block_public_policy
      op: eq
      value: false
    - field: properties.storage.controls.restrict_public_buckets
      op: eq
      value: false
```

**Projects that would trigger:** Discourse (bucket 1), Strapi, Immich
(homelab bucket from FUSE debugging), Ghost (adapter default).

**Severity:** Medium — latent risk, not active exposure.

---

### 2. CTL.S3.TAG.001 — Data Classification Tag Required

**Pattern source:** Across ALL projects. Tag-conditional controls
(PUBLIC.002, ENCRYPT.003, LIFECYCLE.001, LOCK.001) only fire when
tags are present. If a bucket has no `data-classification` tag at all,
every tag-conditional control silently passes — even if the bucket
contains PHI, PII, or confidential data.

**Gap:** No control enforces that buckets MUST have a classification
tag. The entire tag-conditional control subsystem is inert against
untagged buckets.

**Why it matters:** Every single project in the analysis uses S3 buckets
without data classification tags by default. Strapi, Immich, Mastodon,
Discourse, Terraform, Gitea, ClickHouse, Spark, Sentry, Airflow, Loki,
Harbor, Restic, Thanos, Paperless-ngx, KeyDB, MLflow, Dagster, Velero,
Ghost, Directus, Serverless — NONE of them set classification tags out
of the box. This means CTL.S3.PUBLIC.002 (no public PHI buckets) would
never fire on a Paperless-ngx bucket storing scanned tax returns because
nobody tagged it `data-classification=phi`.

```yaml
id: CTL.S3.TAG.001
name: Data Classification Tag Required
type: unsafe_state
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.tags.data-classification
      op: not_exists
      value: true
```

**Projects that would trigger:** All 95 test buckets except the
"hardened" variants.

**Severity:** High — this is a meta-control that gates the
effectiveness of every tag-conditional check.

**Requires:** `not_exists` predicate operator (or equivalent). May
already be covered if `exists` was added in healthcare prompt #5.

---

### 3. CTL.S3.DENY_DELETE.001 — Explicit Delete Denial for Non-Admin Principals

**Pattern source:** Rclone (anti-ransomware deny-delete policy), Restic
(ransomware can "manipulate forget into deleting all legitimate
snapshots"), Thanos (compactor deletion as normal operation), Loki
(compactor destroys forensic evidence).

**Gap:** No control checks for explicit DENY statements on
`s3:DeleteObject`. Multiple projects showed that backup/archival buckets
need a positive deny — not just "no one has delete permissions" but
"delete is explicitly blocked for non-admin principals."

**Why it matters:** Rclone's anti-ransomware pattern is the model: the
backup user can PUT objects but the policy DENYs `s3:DeleteObject` for
everyone except the admin role. Without this, a compromised credential
(from the machine being backed up — the exact scenario backups protect
against) can wipe all backup data. Thanos and Loki make it worse because
their compactors MUST delete objects for normal operation, meaning the
service account has legitimate delete permissions that can be abused.

```yaml
id: CTL.S3.DENY_DELETE.001
name: Backup Buckets Must Have Explicit Delete Denial
type: unsafe_state
# Only applies to buckets tagged as backup/archive targets
unsafe_predicate:
  all:
    - field: properties.tags.purpose
      op: in
      value: ["backup", "archive", "disaster-recovery"]
    - field: properties.storage.policy.has_explicit_delete_deny
      op: eq
      value: false
```

**New canonical field required:**
`properties.storage.policy.has_explicit_delete_deny` — boolean indicating
whether the bucket policy contains a DENY effect on `s3:DeleteObject` or
`s3:DeleteObjectVersion`.

**Projects that would trigger:** Rclone (bucket 1 — correctly has deny,
so it would PASS), Restic, Immich backups, Velero, Litestream, Terraform
state, any backup-tagged bucket without the deny.

**Severity:** High for backup/DR buckets — this is the ransomware
protection control.

---

### 4. CTL.S3.LISTING.001 — Public Listing More Dangerous Than Public Read

**Pattern source:** Mastodon (intentionally public-read objects but
listing MUST be denied), ClickHouse (public datasets where ListBucket to
`*` exposes ALL dataset names including private ones), Gitea (mixed
public/private packages in one bucket).

**Gap:** `CTL.S3.PUBLIC.001` treats `public_read` and `public_list` as
equivalent dangers via `any`. But in practice, public listing is
categorically MORE dangerous than public read — it enables enumeration
of ALL objects (including ones the operator didn't intend to expose) and
reveals bucket structure, naming conventions, and potentially sensitive
metadata (object keys often contain user IDs, dates, internal project
names).

**Why it matters:** Mastodon's media objects are INTENTIONALLY publicly
readable (federated social media requires it). But `s3:ListBucket` to
`*` would let anyone enumerate ALL media URLs — including suspended
users' content that should be inaccessible. The Gitea case is worse:
listing exposes private package NAMES even if the packages themselves
can't be downloaded.

**This is already partially covered by PUBLIC.001's `public_list` check.**
The gap is that PUBLIC.001 fires the same severity for `public_list` as
for `public_read`. Consider either:
- A separate control with CRITICAL severity for listing, or
- A severity field in the control YAML (not currently supported).

**Recommendation:** If the control DSL supports severity levels, make
this a severity enhancement to PUBLIC.001. If not, create a separate
control:

```yaml
id: CTL.S3.LISTING.001
name: No Public Bucket Listing (Critical)
type: unsafe_state
unsafe_predicate:
  field: properties.storage.visibility.public_list
  op: eq
  value: true
```

**Severity:** Critical — enumeration enables targeted attacks.

---

### 5. CTL.S3.EVENT.001 — Event Notification for High-Impact Buckets

**Pattern source:** Harbor (silent layer replacement), Serverless
Framework (code zip tampering = code execution), Terraform (state
tampering = infrastructure manipulation), Apache Iceberg (metadata
tampering = query redirection).

**Gap:** No control checks for S3 event notification configuration.
Four projects showed patterns where S3 object modifications have
extreme downstream impact — code execution (Serverless), supply chain
poisoning (Harbor), infrastructure manipulation (Terraform state), or
query engine hijacking (Iceberg metadata). Real-time detection of
tampering via `s3:ObjectCreated:*` / `s3:ObjectRemoved:*` events to
SNS/SQS/Lambda is the first line of defense.

**Why it matters:** Versioning preserves history for forensics, but
event notifications provide REAL-TIME alerting. Without them, a tampered
Serverless deployment zip executes in production before anyone notices.
Harbor image layer replacement propagates to every `docker pull` before
detection.

**New extraction required:** `aws_s3_bucket_notification` Terraform
resource. Canonical fields:
- `properties.storage.notifications.configured` (boolean)
- `properties.storage.notifications.event_types` (list of event filters)

```yaml
id: CTL.S3.EVENT.001
name: Event Notification Required for Critical Buckets
type: unsafe_state
unsafe_predicate:
  all:
    - field: properties.tags.criticality
      op: in
      value: ["critical", "high"]
    - field: properties.storage.notifications.configured
      op: eq
      value: false
```

**Projects that would trigger:** Serverless deployment buckets, Harbor
registries, Terraform state buckets, Iceberg metadata buckets — IF
tagged appropriately.

**Severity:** Medium — defense-in-depth, not a primary control.

**Effort:** Medium — requires new Terraform resource extraction.

---

### 6. CTL.S3.POLICY.PRINCIPAL_STAR.001 — Deny-Only for Wildcard Principal Policies

**Pattern source:** Mastodon, ClickHouse, Spark, and multiple projects
where `Principal: "*"` appears in bucket policies. Some are intentional
(Mastodon public media), some accidental (Spark cross-account share
that should be scoped).

**Gap:** `CTL.S3.NETWORK.001` (designed, not shipped) checks that
wildcard-principal policies have network conditions (IP/VPC). But
there's a more fundamental check: `Principal: "*"` should ONLY appear
in DENY statements, never in ALLOW statements, unless accompanied by
conditions. This is AWS's own best practice.

**Why it matters:** The policy condition analysis (CTL.S3.NETWORK.001)
handles the "Principal: * WITH conditions" case. But many projects have
`Principal: "*"` in ALLOW statements with NO conditions at all — Strapi,
Discourse, Sentry, Mastodon. A simple "Principal: * only in Deny
effects" control catches the most dangerous pattern without needing
the complex condition key analysis.

**New canonical field required:**
`properties.storage.policy.has_allow_star_principal` — boolean indicating
whether any ALLOW statement uses `Principal: "*"` or `Principal: {"AWS": "*"}`.

```yaml
id: CTL.S3.POLICY.PRINCIPAL_STAR.001
name: No Allow Statements with Wildcard Principal
type: unsafe_state
unsafe_predicate:
  field: properties.storage.policy.has_allow_star_principal
  op: eq
  value: true
```

**Relationship to existing controls:** Overlaps with PUBLIC.001 (which
catches the downstream EFFECT of wildcard principal + read action). But
this control catches it at the POLICY STRUCTURE level — it would fire
even for `s3:PutObject` to `*` or `s3:DeleteObject` to `*`, which
PUBLIC.001/003 might miss if the action isn't mapped to the
`public_read`/`public_write` computation.

**Projects that would trigger:** Mastodon, ClickHouse (shared datasets),
Spark (shared analytics), Strapi, Discourse (backups with public policy
remnants), Sentry.

**Severity:** High — wildcard principal in Allow is the root cause of
most public bucket incidents.

---

### 7. CTL.S3.STALE_POLICY.001 — Detect Over-Broad IAM Actions

**Pattern source:** Airflow (`AmazonS3FullAccess` managed policy), Spark
(cross-account `s3:*`), Rclone (`s3:*` for write access), Gitea
(wildcard action for data bucket), Loki (wildcard for chunk management).

**Gap:** `CTL.S3.ACCESS.002` detects `s3:*` wildcard actions. But the
analysis revealed a spectrum of over-broad permissions that aren't
`s3:*` but are still dangerous:
- `s3:Put*` (grants PutBucketPolicy — policy takeover)
- `s3:Delete*` (grants DeleteBucket — total destruction)
- `s3:Get*` + `s3:List*` (full read access when only specific paths
  needed)

**Why it matters:** Airflow's official EKS deployment guide recommends
the `AmazonS3FullAccess` managed policy, which grants `s3:*` on ALL
buckets in the account, not just the logging bucket. But even a
"scoped" policy using `s3:Put*` is dangerous because it includes
`s3:PutBucketPolicy` — the ability to change the bucket's own access
policy.

**Enhancement to ACCESS.002:** Rather than a new control, extend the
canonical field to detect DANGEROUS action patterns beyond just `s3:*`:

New canonical fields:
- `properties.storage.access.has_admin_actions` — boolean for actions
  that include `s3:PutBucket*`, `s3:DeleteBucket*`, or `s3:*`
- `properties.storage.access.dangerous_actions` — list of specific
  dangerous action grants found

```yaml
id: CTL.S3.ACCESS.003
name: No Administrative S3 Actions in Application Policies
type: unsafe_state
unsafe_predicate:
  field: properties.storage.access.has_admin_actions
  op: eq
  value: true
```

**Projects that would trigger:** Airflow, Spark, Rclone, Gitea, Loki,
Dagster, most projects with broadly-scoped IAM.

**Severity:** High — `s3:PutBucketPolicy` is privilege escalation.

**Effort:** Medium — requires parsing individual actions in policy
analysis, not just checking for `s3:*`.

---

### 8. CTL.S3.MIXED_SENSITIVITY.001 — Mixed Data Classification in Single Bucket

**Pattern source:** Gitea (6 data types in one bucket — source code,
binaries, ML models, documents, user data, attachments), ClickHouse
(public datasets mixed with private data), Directus (multi-tenant user
content), Loki (multi-tenant logs), Harbor (public + private images).

**Gap:** No control detects when a single bucket contains data of
mixed sensitivity levels. This is architecturally distinct from
tag-conditional checks — it's about the ABSENCE of data segregation.

**Why it matters:** Gitea's single `gitea-data` bucket containing
proprietary source code alongside public avatars means a single
misconfiguration exposes everything at the highest sensitivity level.
Directus storing all tenants' uploads (patient records, financial
documents, employee files) in one bucket means tenant isolation depends
entirely on application logic, not S3 access controls.

**Implementation challenge:** This is hard to detect from a Terraform
snapshot alone — you can't see WHAT DATA is in a bucket from its config.
However, you CAN detect the conditions that CREATE mixed-sensitivity
scenarios:
- Multiple S3 prefix paths in application config pointing to same bucket
- Multiple applications/services writing to same bucket
- Bucket tagged with multiple data-classification values

**Recommendation:** This may be better as a FINDING/ADVISORY rather
than a control, since it requires understanding application
architecture beyond S3 configuration.

**Severity:** High conceptually, but LOW detectability from Terraform
alone.

---

## Summary: Priority-Ranked Controls (from 40-project analysis)

| Priority | ID | Name | Status | Notes |
|----------|----|------|--------|-------|
| **P0** | GOVERNANCE.001 | Data Classification Tag Required | **Shipped** | Uses `missing` operator |
| **P0** | CONTROLS.001 | Public Access Block Must Be Enabled | **Shipped** | Checks `public_access_fully_blocked` |
| **P1** | ENCRYPT.004 | Confidential/Internal Requires KMS | **Shipped** | Uses `in` + `ne` operators |
| **P1** | PUBLIC.006 | Latent Public Bucket Listing | **Shipped** | Checks `latent_public_list` |
| **P1** | DENY_DELETE.001 | Explicit Delete Denial for Backups | Candidate | Requires policy DENY analysis |
| **P1** | POLICY.PRINCIPAL_STAR.001 | No Allow with Wildcard Principal | Candidate | Requires policy Allow analysis |
| **P2** | ACCESS.003 | No External Write Access | **Shipped** | New `has_external_write` computed field |
| **P2** | EVENT.001 | Event Notification for Critical Buckets | Candidate | Requires new resource extraction |
| **P2** | LISTING.001 | Public Listing (Critical Severity) | Candidate | Severity in DSL or new control |
| **INFO** | MIXED_SENSITIVITY.001 | Mixed Data in Single Bucket | Candidate | Architectural advisory |

---

## Patterns Observed but NOT Control-Addressable

These patterns appeared across multiple projects but can't be detected
from S3 bucket configuration alone:

| Pattern | Projects | Why Not Detectable |
|---------|----------|-------------------|
| Credentials in SQL/URL/config | ClickHouse, Loki, Airflow | Application config, not S3 config |
| RBAC bypass via direct S3 access | Directus, Gitea | Requires comparing app-level vs S3-level controls |
| EXIF/metadata leakage | Immich, Directus | Object content, not bucket config |
| Deployment bucket sprawl | Serverless Framework | Requires counting buckets per pattern |
| Cleanup gap (orphaned objects) | Sentry, Serverless | Object lifecycle, not bucket config |
| Cross-environment aggregation | Thanos | Requires understanding env topology |
| Multi-tenant path isolation | Loki, Directus | Requires understanding tenant model |

---

## Impact on CSA Coverage Score

Current coverage: ~75-85% (depending on shipped vs designed controls).

Adding P0 controls (TAG.001 + PAB.BUCKET.001): +3% → ~88%
Adding P1 controls (DENY_DELETE, PRINCIPAL_STAR, ACCESS.003): +5% → ~93%
Adding P2 controls + shipping designed controls: +4% → ~97%

The remaining ~3% is the non-detectable patterns above — they require
runtime analysis, application-layer understanding, or multi-resource
correlation that goes beyond single-bucket configuration checking.
