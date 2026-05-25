# Shape-B CIA fixtures

JSONL fact streams that exercise the Phase 7 access-graph pipeline
against incident shapes drawn from public breach analyses. Each
fixture is a hand-authored set of (subject, predicate, object)
triples in the same shape `stave export-sir --format jsonl`
produces.

Use these to drive the G6 triage report with real-distribution
data — see `stave/docs/coverage/cia-novel-violations.md` for the
classification framework.

## Running a fixture end-to-end

```bash
# From the stave/ directory:
FIXTURE=reasoning/souffle/iam/fixtures/cap-one-pattern.jsonl
OUTDIR=/tmp/cia-cap-one

# Step 1: extract facts.
go run ./reasoning/souffle/iam/extract.go \
    -jsonl  "$FIXTURE" \
    -out    "$OUTDIR/facts"

# Step 2: run the Datalog rules.
mkdir -p "$OUTDIR/souffle"
souffle reasoning/souffle/iam/rules.dl \
    -F "$OUTDIR/facts" \
    -D "$OUTDIR/souffle" \
    -I reasoning/souffle/iam

# Step 3: emit CIA findings.
go run ./reasoning/souffle/iam/emit_findings.go \
    -souffle-out "$OUTDIR/souffle" \
    -out         "$OUTDIR/cia-findings.json"

# Step 4: inspect.
cat "$OUTDIR/souffle/_g1_derived_count.csv"
jq '.findings[] | {control_id, asset_id, corpus_reference}' \
    "$OUTDIR/cia-findings.json"
```

## Fixtures shipped

### `cap-one-pattern.jsonl`

Mirrors the Capital One 2019 incident shape: web application role
with broad S3 permissions on a PII-tagged bucket; role is untagged
against the bucket's ownership tag, producing an unauthorized
effective access path.

**Expected findings (per the G3 + G4/G5 model):**
- `violation_c` × N rows (s3:Get* reads on the PII bucket)
- `violation_i` × M rows (any write actions the role has on the
  PII bucket)

**Triage classification:** Real novel (this is the Capital One shape;
no existing compound CEL covers "untagged role with broad S3 on
PII-tagged bucket via access graph").

### `cognito-anon-pattern.jsonl`

Mirrors the recurring Cognito misconfiguration shape: an identity
pool admits unauthenticated principals, maps them to an IAM role
with broad data-plane grants, and the data-plane resource is
PII-tagged.

**Expected findings:**
- `violation_c` for dynamodb:GetItem / dynamodb:Query reaches
- `violation_i` for dynamodb:PutItem reaches

**Triage classification:** Real novel for the data-plane reach;
the Cognito anonymous-reachability shape itself is partially
covered by the existing `examples/engines/souffle/reachability.dl`
program but no compound CEL control flags the
"anonymous-reachable + DataClassification=PII" composition.

## Caveat — JSONL shape vs full out.v0.1 snapshots

These fixtures are JSONL fact streams, NOT full Stave snapshots
(`obs.v0.1` JSON). The extractor's `-jsonl` mode skips the
`stave export-sir` step and reads the facts directly. To run the
pipeline against a real production snapshot, use `-snapshot`
instead and let the extractor invoke `stave export-sir
--format jsonl`.

The JSONL form is small and easy to author / audit; the snapshot
form is what production deployments produce. Both work end-to-end.
