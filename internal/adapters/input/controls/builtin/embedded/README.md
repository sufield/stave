# Stave Controls

This directory contains control definitions organized by domain.

## MVP 1.0 S3 Canonical Controls

The canonical S3 control set lives in **`s3/`** and its subdirectories. This is
the directory tree loaded by `stave apply --profile mvp1-s3` and the recommended `--controls`
path for S3 evaluation with `stave apply`.

```bash
# Using apply --profile mvp1-s3 (loads s3/ automatically, recursively)
stave apply --profile mvp1-s3 --input observations.json

# Using apply with explicit path
stave apply --controls controls/s3 --observations ./obs
```

### What's in `s3/`

40 controls across 15 subdirectories:

| Subdir | IDs | Purpose |
|--------|-----|---------|
| `access/` | ACCESS.001-003, AUTH.READ.001, AUTH.WRITE.001 | External access, wildcard actions, external write, authenticated-users read/write |
| `acl/` | ACL.ESCALATION.001, ACL.RECON.001, ACL.FULLCONTROL.001 | ACL modification, ACL readability, FULL_CONTROL grants |
| `public/` | PUBLIC.001-006, PUBLIC.LIST.001-002, ACL.WRITE.001, WEBSITE.PUBLIC.001 | Public read, list, write, ACL, latent exposure, website hosting |
| `encrypt/` | ENCRYPT.001-004 | At-rest, in-transit, PHI KMS, sensitive KMS |
| `logging/` | LOG.001 | Access logging |
| `versioning/` | VERSION.001-002 | Versioning, MFA delete |
| `lifecycle/` | LIFECYCLE.001-002 | Retention rules, PHI expiration minimum |
| `lock/` | LOCK.001-003 | Object lock for compliance, PHI mode, retention |
| `network/` | NETWORK.001 | Public principal without network conditions |
| `governance/` | GOVERNANCE.001 | Data classification tag required |
| `takeover/` | BUCKET.TAKEOVER.001, DANGLING.ORIGIN.001 | Bucket takeover, dangling CloudFront origin |
| `artifacts/` | REPO.ARTIFACT.001 | Repository artifact exposure |
| `tenant/` | TENANT.ISOLATION.001 | Tenant isolation |
| `write_scope/` | WRITE.SCOPE.001, WRITE.CONTENT.001 | Write scope tracking, content-type restrictions |
| `misc/` | INCOMPLETE.001, CONTROLS.001 | Missing data, public access block enforcement |

### Duplicate ID Protection

The YAML loader rejects duplicate control IDs across the entire directory tree.
If two files in any subdirectory contain the same control ID, loading fails with
a clear error naming both files. This prevents silent semantic conflicts.

### Write Scope Classification

The exposure evaluator now covers all 6 standard S3 misconfiguration vectors:

| Finding | Action | Risk |
|---------|--------|------|
| `CTL.S3.PUBLIC.READ` | `s3:GetObject` | Data exfiltration |
| `CTL.S3.PUBLIC.LIST` | `s3:ListBucket` | Object key enumeration |
| `CTL.S3.PUBLIC.WRITE` | `s3:PutObject` | Storage injection (blind or full) |
| `CTL.S3.PUBLIC.ACL.READ` | `s3:GetBucketAcl` | Permission enumeration |
| `CTL.S3.PUBLIC.ACL.WRITE` | `s3:PutBucketAcl` | **Critical** — full bucket takeover via permission escalation |
| `CTL.S3.PUBLIC.DELETE` | `s3:DeleteObject` | Data destruction |

Additional finding types: `ACL.PUBLIC.READ`, `ACL.PUBLIC.WRITE`, `GLOBAL.AUTHENTICATED.READ`,
`WEBSITE.PUBLIC`, `BUCKET.TAKEOVER`.

Wildcard actions (`s3:*`, `*`) correctly trigger all applicable finding types.

The evaluator distinguishes **blind** from **full** public write:

| Write Scope | Condition | Risk |
|-------------|-----------|------|
| `blind` | PutObject allowed, no GetObject or ListBucket | Injection only (upload/overwrite) |
| `full` | PutObject + GetObject or ListBucket allowed | Data breach + injection (upload + read + enumerate) |

Classification uses merged global permissions across policy and ACL sources. When a
single policy statement grants both PutObject and GetObject, the WRITE finding absorbs
the READ finding (actions include both) to avoid double-counting. When read and write
come from different sources (e.g., policy read + ACL write), both findings are emitted
independently.

### `_registry/` Convention

Directories prefixed with `_` are skipped during recursive loading. The optional
`_registry/controls.index.json` file provides a fast-path for large control sets:

```json
{
  "schema_version": "registry.v0.1",
  "files": ["access/CTL.S3.ACCESS.001.yaml", "public/CTL.S3.PUBLIC.001.yaml"]
}
```

When present, the loader reads only the listed files instead of walking the tree.
When absent, the loader falls through to recursive directory walking.

## Directory Structure

```
controls/
├── s3/                       # MVP1 canonical S3 controls (40 files, 15 subdirs)
│   ├── access/               # External access + authenticated-users rules (5 files)
│   ├── acl/                  # ACL privilege escalation rules (3 files)
│   ├── public/               # Public exposure rules (11 files)
│   ├── encrypt/              # Encryption rules (4 files)
│   ├── logging/              # Access logging (1 file)
│   ├── versioning/           # Versioning rules (2 files)
│   ├── lifecycle/            # Lifecycle rules (2 files)
│   ├── lock/                 # Object lock rules (3 files)
│   ├── network/              # Network condition rules (1 file)
│   ├── governance/           # Governance rules (1 file)
│   ├── takeover/             # Bucket takeover rules (2 files)
│   ├── artifacts/            # Repository artifact rules (1 file)
│   ├── tenant/               # Tenant isolation rules (1 file)
│   ├── write_scope/          # Write scope rules (2 files)
│   └── misc/                 # Incomplete data + controls (2 files)
├── exposure/                 # Exposure and visibility domain
│   ├── duration/
│   ├── justification/
│   ├── ownership/
│   ├── recurrence/
│   ├── state/
│   └── visibility/
└── third_party/              # Third-party integration rules
```

## Taxonomy Rules

### Exposure Domain
- **duration**: Time bounds on unsafe exposure states (e.g., max 168h)
- **justification**: Requires documented justification for exposure
- **ownership**: Enforces resource ownership requirements
- **recurrence**: Detects recurring exposure patterns
- **state**: Tracks and enforces exposure state transitions
- **visibility**: Requires exposure status to be known

### Storage Domain (S3)
All S3 controls live in **`s3/`** organized into bounded-context subdirectories.

### Third-Party Domain
- **platform**: Third-party platform boundary violations
- **vendor**: Vendor data boundary enforcement

## Adding a New Control

1. Determine the domain and subdomain based on the taxonomy rules above
2. For S3 controls, place the file in the appropriate subdirectory under `s3/`
3. Create a YAML file with the following structure:

```yaml
dsl_version: ctrl.v1
id: CTL.<CATEGORY>.<TYPE>.<NUMBER>
name: Human-readable name
description: |
  Detailed description of what this control enforces.
domain: <exposure|identity|storage|platforms|third_party>
scope_tags:
  - relevant_tag_1
  - relevant_tag_2
type: <control_type>
params:
  key: value
unsafe_predicate:
  any:
    - field: "properties.field_name"
      op: "eq"
      value: true
```

## Control ID Format

- **CTL.S3.PUBLIC.001**: AWS S3 public access rule #1
- **CTL.S3.INCOMPLETE.001**: S3 incomplete observation rule #1
- **CTL.EXP.DURATION.001**: Exposure duration rule #1
- **CTL.EXP.VISIBILITY.001**: Exposure visibility rule #1
- **CTL.TP.PLATFORM.001**: Third-party platform boundary rule #1
- **CTL.TP.VENDOR.001**: Third-party vendor boundary rule #1

## Stability Rules

1. **Control IDs are stable**: Once assigned, an control ID should not change
2. **File basenames match IDs**: File should be named `{ID}.yaml`
3. **No duplicate IDs**: The YAML loader rejects duplicate IDs with a clear error
