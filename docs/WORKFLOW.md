# Stave Workflow: From Zero to Verified

You know which AWS services you use. Stave tells you what to collect and what its standardized
input must contain; you collect and convert it with your own tools; Stave evaluates it.
**Stave never has AWS credentials and never calls AWS** — it reads `obs.v0.1` observation files
you produce.

Two distinct artifacts, do not conflate them:

| Term | What it is | Who produces it |
|------|-----------|-----------------|
| **Snapshot** | raw provider API output (`aws iam list-roles` JSON) | your collector (AWS CLI, Steampipe, …) |
| **Observation** (`obs.v0.1`) | Stave's standardized input, carrying the derived signals controls read | an **extractor** that converts snapshots → observations |

```
discover ─▶ plan ─▶ collect ─▶ convert ─▶ apply ─▶ fix ─▶ check ─▶ repeat
 (what to    (what     (raw       (snapshots  (-o reads          (resolved/
  collect +   gets      snapshots)  → obs.v0.1) observations)      remaining/
  signals)    checked)              ▲ NOT Stave                     new)
```

## Step 1 — Discover: what to collect, and what the observations must contain

```bash
stave discover --services iam,s3,ec2,lambda,cloudtrail
```

Resolves the packs covering those services and merges their requirements: the read-only **API
calls** to collect (your snapshots), the **observation signals** the converted `obs.v0.1` must
carry (e.g. `identity.permission_drift.unused_service_ratio`), and the **minimum collector IAM
permissions**. Hand it to compliance — every call is read-only. `--format json` for tooling.

## Step 2 — Plan: what will Stave check?

```bash
stave plan --services iam,s3,ec2,lambda,cloudtrail
```

Controls per service × severity, plus a severity-weighted collection order (collect the
highest-impact data first).

> `stave plan` previews **what will be checked** (before you collect). `stave apply --dry-run`
> checks whether already-converted **observations are ready** (after you convert). Different jobs.

## Step 3 — Collect (your tools): snapshots

Run the manifest's API calls with whatever produces JSON — AWS CLI, Steampipe, your internal
tool — into a raw snapshot directory:

```bash
mkdir -p snapshots
aws iam list-roles  --output json > snapshots/iam-roles.json
aws s3api list-buckets --output json > snapshots/s3-buckets.json
# … the rest of the calls from `stave discover` …
```

## Step 4 — Convert (extractor): snapshots → observations

Snapshots are raw API shapes; Stave reads the standardized `obs.v0.1` form. An **extractor**
transforms them, computing the observation signals from Step 1. This is **not** Stave — it's
your collector/extractor (`aws + jq`, Steampipe transforms, or a provided adapter):

```bash
# e.g. the repo's collector: collects raw AWS CLI JSON into ./acct/raw, then
# runs `stave transform` to write obs.v0.1 into ./acct/observations
bash scripts/aws-snapshot.sh ./acct
# or convert pre-collected raw snapshots yourself: stave transform -i raw/ -o observations/
```

The boundary: Stave reads `observations/*.json`. How those files get there is the extractor's
job, never Stave's.

## Step 5 — Apply: evaluate per service group, get findings fast

```bash
# doctest:skip — requires observation data
stave apply --services iam -o ./observations      # IAM findings in seconds
stave apply --services s3  -o ./observations      # then S3, …
stave apply -o ./observations                     # full catalog over everything converted
```

`-o` / `--observations` reads the `obs.v0.1` observations. `--services` scopes evaluation to
those services' controls (a different `policy_fingerprint` proves the scope is real). Exit code
**3** means violations were found — a successful evaluation, not an error.

## Step 6 — Fix

Remediate the criticals first (each finding carries a `remediation` hint and a parameterized
`fix_plan.command`). Re-collect the affected service group and re-convert → new observations.

## Step 7 — Check: did the fixes work?

```bash
# doctest:skip — requires observation data
stave check --before ./observations --after ./observations-fixed
```

Reports **RESOLVED / STILL-FAILING / NEW**. Each `--after` can become the next `--before`.

## Step 8 — Repeat

Fix more, re-collect, re-convert, `check` again. Each observation set is a timestamped artifact;
the diff between two is the proof of remediation.

---

## The whole loop, copy-paste

```bash
# doctest:skip — requires observation data
stave discover --services iam,s3,ec2,lambda,cloudtrail   # 1. what to collect + signals
stave plan     --services iam,s3,ec2,lambda,cloudtrail   # 2. what gets checked
# 3. collect raw snapshots with your tools (commands printed by discover)
# 4. convert snapshots -> obs.v0.1 observations with your extractor (NOT Stave)
stave apply --services iam -o ./observations             # 5. findings, per group
# 6. fix, re-collect, re-convert -> ./observations-fixed
stave check --before ./observations --after ./observations-fixed   # 7. resolved/remaining/new
```

`scripts/quickstart.sh` runs steps 1–2 (and 5 if you pass a converted observations directory).

## What you never have to know

| You don't ask | Because |
|---------------|---------|
| "Which snapshots do I need?" | `stave discover --services …` lists the exact read-only API calls |
| "Which controls should I run?" | `stave plan` shows them by service and severity |
| "Does Stave need my AWS credentials?" | No. Never. It reads the observations you converted. |
| "I fixed things — now what?" | `stave check --before --after` |

You **do** convert snapshots into observations — that's the one step Stave never does for you.
