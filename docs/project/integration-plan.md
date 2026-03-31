# Integration Plan

Technical plan for stave integrations with complementary tools.
Each integration includes the demo scenario and implementation approach.

Stave's positioning: **offline configuration safety evaluator**. It
consumes snapshots (JSON), evaluates controls (YAML/CEL), and produces
findings (JSON/SARIF/text). Every integration follows this pattern:
something produces data stave consumes, or something consumes data
stave produces.

---

## Priority 1: Already Implemented

These integrations exist today and need demos, not code.

### SARIF → GitHub Code Scanning

**Status**: Done. `--format sarif` on `apply` and `security-audit`.

**Demo**:
```yaml
# .github/workflows/stave.yml
name: Stave Security Scan
on: [push, pull_request]
permissions:
  security-events: write
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          stave apply \
            --controls controls/s3 \
            --observations observations \
            --max-unsafe 7d \
            --format sarif > results.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: stave
```

**Result**: Violations appear as annotations in PR diffs and in the
Security tab. No custom UI needed.

### JSON → jq / DefectDojo / Custom Pipelines

**Status**: Done. `--format json` produces clean `out.v0.1` JSON on
stdout with no stderr noise (machine format auto-suppresses progress).

**Demo**:
```bash
# Count violations
stave apply --format json | jq '.summary.violations'

# Extract violated control IDs
stave apply --format json | jq -r '.findings[].control_id' | sort -u

# Feed to DefectDojo
stave apply --format json > findings.json
curl -X POST https://defectdojo.example.com/api/v2/import-scan/ \
  -F 'file=@findings.json' -F 'scan_type=SARIF'
```

### CI/CD Gating (GitHub Actions, GitLab CI)

**Status**: Done. Exit codes, baselines, gate command, env vars.

**Demo**: See `stave-guide/how-to/ci-cd-integration.md` for complete
GitHub Actions and GitLab CI workflows.

---

## Priority 2: Snapshot Source Integrations (build demos)

These produce data stave can consume. Each needs a small extractor
script that converts the tool's output to `obs.v0.1` JSON.

### Terraform State → Stave Observations

**What**: Convert `.tfstate` S3 resources to `obs.v0.1` snapshots.

**Demo script** (`extractors/terraform-s3.sh`):
```bash
#!/bin/bash
# Extract S3 bucket configs from Terraform state
terraform show -json | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "terraform-state", tool: "terraform"},
  captured_at: (now | todate),
  assets: [.values.root_module.resources[]
    | select(.type == "aws_s3_bucket")
    | {
        id: .values.bucket,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: {
          storage: {
            kind: "bucket",
            name: .values.bucket,
            tags: (.values.tags // {})
          }
        }
      }
  ]
}'
```

**Pipeline**:
```bash
terraform show -json | ./extractors/terraform-s3.sh > observations/snap.json
stave apply --controls controls/s3 --observations observations --format sarif
```

**Effort**: Shell script + jq. No stave code changes.

### AWS Config → Stave Observations

**What**: Convert AWS Config resource snapshots to `obs.v0.1`.

**Demo script** (`extractors/aws-config-s3.sh`):
```bash
#!/bin/bash
# Extract S3 configs from AWS Config
aws configservice get-resource-config-history \
  --resource-type AWS::S3::Bucket \
  --resource-id "$1" \
  --limit 1 \
  --output json | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "aws-config", tool: "aws-cli"},
  captured_at: .configurationItems[0].configurationItemCaptureTime,
  assets: [.configurationItems[] | {
    id: .resourceId,
    type: "aws_s3_bucket",
    vendor: "aws",
    properties: (.configuration | fromjson)
  }]
}'
```

**Effort**: Shell script + jq. No stave code changes.

### Steampipe → Stave Observations

**What**: Use Steampipe SQL to query S3 configs, output as `obs.v0.1`.

**Demo**:
```bash
steampipe query --output json "
  select
    name as id,
    'aws_s3_bucket' as type,
    'aws' as vendor,
    jsonb_build_object(
      'storage', jsonb_build_object(
        'kind', 'bucket',
        'name', name,
        'tags', tags
      )
    ) as properties
  from aws_s3_bucket
" | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "steampipe", tool: "steampipe"},
  captured_at: (now | todate),
  assets: .
}'
```

**Effort**: SQL query + jq wrapper. No stave code changes.

---

## Priority 3: Output Integrations (build demos)

These consume stave's findings.

### Cloud Custodian (Detect + Act)

**What**: Stave detects misconfigurations, Cloud Custodian remediates.

**Demo**:
```bash
# Stave detects public buckets
stave apply --format json | jq -r '.findings[].resource_id' > violating-buckets.txt

# Cloud Custodian remediates
cat > policy.yml <<EOF
policies:
  - name: block-public-buckets
    resource: s3
    filters:
      - type: value
        key: Name
        op: in
        value_from:
          url: file://violating-buckets.txt
    actions:
      - type: set-public-access-block
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
EOF
custodian run -s output policy.yml
```

**Pattern**: Stave produces the list, Custodian acts on it.

### Slack / PagerDuty Webhook

**What**: Send critical findings to Slack on CI failure.

**Demo**:
```bash
# In GitHub Actions
stave apply --format json > findings.json || true
VIOLATIONS=$(jq '.summary.violations' findings.json)
if [ "$VIOLATIONS" -gt 0 ]; then
  curl -X POST "$SLACK_WEBHOOK" \
    -H 'Content-type: application/json' \
    -d "{\"text\": \"Stave found $VIOLATIONS violations in $(git rev-parse --short HEAD)\"}"
fi
```

**Effort**: Webhook call in CI. No stave code changes.

---

## Priority 4: Developer Workflow Integrations (build)

### pre-commit Hook

**What**: Run stave before every commit.

**Demo** (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: local
    hooks:
      - id: stave-validate
        name: Stave validate
        entry: stave validate --controls controls --observations observations --strict
        language: system
        pass_filenames: false
        always_run: true
```

**Effort**: Config file only. No stave code changes.

### Atlantis Post-Plan Check

**What**: Run stave after `terraform plan` in Atlantis PR workflow.

**Demo** (`atlantis.yaml`):
```yaml
version: 3
projects:
  - dir: infra
    workflow: stave-check
workflows:
  stave-check:
    plan:
      steps:
        - init
        - plan
    policy_check:
      steps:
        - run: |
            terraform show -json $PLANFILE | \
              ./extractors/terraform-s3.sh > /tmp/snap.json
            stave apply --controls controls/s3 \
              --observations /tmp \
              --max-unsafe 0s --format text
```

**Effort**: Atlantis config + extractor script. No stave code changes.

---

## Priority 5: Policy Engine Alignment (future)

### OPA / Conftest

**What**: Export stave controls as Rego policies for OPA/Conftest users.

**Approach**: Build a `stave export --format rego` command that
translates `ctrl.v1` YAML predicates to equivalent Rego rules. This
lets teams that already use OPA adopt stave's control logic without
switching tools.

**Effort**: New `export` subcommand. Medium code change.

### driftctl Complement

**What**: driftctl detects IaC-to-live drift. Stave evaluates the live
config's safety. Run both in the same pipeline.

**Demo**:
```bash
# driftctl finds what changed
driftctl scan --from tfstate://terraform.tfstate --output json > drift.json

# Stave evaluates the live config
stave apply --format json > safety.json

# Correlate: which drifted resources are also unsafe?
jq -r '.findings[].resource_id' safety.json | \
  xargs -I{} jq --arg id {} '.managed[] | select(.id == $id)' drift.json
```

---

## What Stave Does NOT Need to Build

| Integration | Why not |
|---|---|
| Live AWS API calls | Stave is offline-only; extractors handle API calls |
| Container scanning | Out of scope; Trivy/Grype cover this |
| Secret scanning | Out of scope; Gitleaks/TruffleHog cover this |
| Policy authoring UI | Out of scope; Stave is a CLI, not a platform |
| Kubernetes runtime | Out of scope unless K8s config snapshots are added |

---

## Integration Architecture

Every integration follows one of two patterns:

```
Pattern A: Something → obs.v0.1 → Stave → Findings
(Terraform, AWS Config, Steampipe, extractors)

Pattern B: Stave → Findings → Something
(SARIF/GitHub, jq, DefectDojo, Slack, Cloud Custodian)
```

Stave never needs to import another tool's library or call another
tool's API. The observation contract (`obs.v0.1`) and the output
contract (`out.v0.1` / SARIF) are the integration surfaces. New
integrations are additive scripts, not code changes.

---

## Demo Priority Order

1. **GitHub Actions + SARIF** — show violations in PR diffs (done, needs demo repo)
2. **Terraform state extractor** — shell script, 20 lines
3. **pre-commit hook** — config file, 10 lines
4. **AWS Config extractor** — shell script, 15 lines
5. **Cloud Custodian detect+act** — two-command pipeline
6. **Steampipe extractor** — SQL query + jq
7. **Slack webhook** — 5-line curl in CI
8. **Atlantis post-plan** — config file + extractor
