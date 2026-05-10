# Stave Examples Catalog

**49 fixture pairs** across
**20 example scenarios**, each tested
against every available reasoning engine.

Every scenario ships a vulnerable fixture and a remediated
fixture. The matrix below shows what each engine reveals.
Pick the scenario closest to your environment and adapt it.

## Demo Scenarios (Start Here)

Entry-level S3 misconfiguration walkthroughs migrated from the
legacy `docs-content/demo/` Docker surface. Every demo runs in
the Codespaces devcontainer with `bash run.sh` — no Docker
image to build, no separate launcher.

- **[demo-s3-public-read](demo-s3-public-read/)** — Bucket policy with `Principal: "*"` + Public Access Block disabled
- **[demo-s3-acl-escalation](demo-s3-acl-escalation/)** — ACL grants broader access than the bucket policy admits
- **[demo-s3-acl-write](demo-s3-acl-write/)** — Public write via ACL misconfiguration
- **[demo-s3-hipaa-compliance](demo-s3-hipaa-compliance/)** — Multi-violation PHI bucket against the HIPAA profile
- **[demo-s3-upload-hardening](demo-s3-upload-hardening/)** — Unrestricted upload surface
- **[demo-s3-data-governance](demo-s3-data-governance/)** — Data classification + lifecycle hygiene
- **[demo-s3-tool-blind-spot](demo-s3-tool-blind-spot/)** — What single-resource scanners miss

These are the first stops for an early adopter — a single
asset, a clear violation, encoding-verified output. Once the
shape is familiar, the multi-engine examples below show how
external reasoning engines (Z3, Soufflé, Clingo, PySAT) score
the same fact base.

## By Attack Pattern

### Anonymous Access via Identity Pools

- **[cognito-self-register-to-aws-creds](cognito-self-register-to-aws-creds/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. CEL findings — remediated-config: 0, writeup-config: 1.

### IAM Privilege Escalation

- **[iam-21-privesc-5-patterns](iam-21-privesc-5-patterns/multi-engine-results.md)** — 4 fixture(s): partial-deny, real-world-pattern3, remediated, rhino-vulnerable. CEL findings — partial-deny: 1, real-world-pattern3: 0, remediated: 0, rhino-vulnerable: 1.
- **[iam-overpermission-wildcard](iam-overpermission-wildcard/multi-engine-results.md)** — 4 fixture(s): after, before, bybit-pattern-after, bybit-pattern-before. CEL findings — after: 0, before: 1, bybit-pattern-after: 0, bybit-pattern-before: 0.
- **[iam-attach-user-policy-self](iam-attach-user-policy-self/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[iam-autoscaling-privesc-bypass](iam-autoscaling-privesc-bypass/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. CEL findings — remediated-config: 0, writeup-config: 1.

### Cross-Service Trust Chains

- **[iam-multi-hop-trust](iam-multi-hop-trust/multi-engine-results.md)** — 2 fixture(s): remediated, vulnerable. CEL findings — remediated: 0, vulnerable: 0.
- **[sns-secrets-compound-chain](sns-secrets-compound-chain/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. CEL findings — remediated-config: 0, writeup-config: 0.

### SSRF → Credential Theft Chains

- **[ecs-ssrf-credential-theft](ecs-ssrf-credential-theft/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. ECS task-metadata variant of the SSRF credential-theft pattern; chain fires when 2 of `{TASKMETADATA.001, METADATA.CREDENTIAL.001, VPC.SG.EGRESS.001}` are set. CEL findings — remediated-config: 0, writeup-config: 3.
- **[imds-ssrf-chain](imds-ssrf-chain/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. EC2-instance variant — Capital One breach pattern (IMDSv1 + hop > 1). Chain fires when 2 of `{IMDSV2.001, IMDSV2.002, IMDS.HOPLIMIT.001}` are set. CEL findings — remediated-config: 0, writeup-config: 2.

### S3 Exposure & Tenant Boundaries

- **[s3-public-read-policy](s3-public-read-policy/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[s3-public-list-policy](s3-public-list-policy/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[s3-broad-write-scope](s3-broad-write-scope/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[s3-tenant-prefix-isolation](s3-tenant-prefix-isolation/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[s3-bucket-name-dangling](s3-bucket-name-dangling/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[s3-cross-account-replication-overperm](s3-cross-account-replication-overperm/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config. CEL findings — remediated-config: 0, writeup-config: 0.
- **[s3-dotgit-readable](s3-dotgit-readable/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.

### Cognito User Pools

- **[cognito-no-mfa-advanced-security](cognito-no-mfa-advanced-security/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.

### EKS / Kubernetes

- **[eks-aws-auth-template-injection](eks-aws-auth-template-injection/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.
- **[eks-rbac-webhook-config-access](eks-rbac-webhook-config-access/multi-engine-results.md)** — 2 fixture(s): after, before. CEL findings — after: 0, before: 1.

### Defense Evasion

- **[cloudtrail-stop-logging](cloudtrail-stop-logging/multi-engine-results.md)** — 4 fixture(s): after, before, data-events-after, data-events-before. CEL findings — after: 0, before: 1, data-events-after: 0, data-events-before: 0.

### Network / API Boundaries

- **[apigw-private-api-scoped-deny](apigw-private-api-scoped-deny/multi-engine-results.md)** — 3 fixture(s): broadened-allow, remediated-config, writeup-config. CEL findings — broadened-allow: 0, remediated-config: 0, writeup-config: 0.

### Lifecycle Drift

- **[staging-stale-endpoint](staging-stale-endpoint/multi-engine-results.md)** — 4 fixture(s): active-staging, prod-dormant, stale-staging, stale-staging-public. CEL findings — active-staging: 0, prod-dormant: 0, stale-staging: 1, stale-staging-public: 2.

## By Engine — "I want to …"

| Question | Engine | How |
|---|---|---|
| Detect per-control violations on a snapshot | **CEL** (built-in) | `stave apply --observations …` |
| Prove an attack path *exists* | **Z3 / cvc5 / Yices** | `stave export-sir --format smt2 \| z3 -in` with a query |
| Enumerate the full blast radius | **Soufflé** | `bash examples/souffle-reachability/run.sh` |
| Enumerate every constraint violation | **Clingo** | `bash examples/clingo-constraints/run.sh` |
| Derive a proof tree ("why is this reachable?") | **Prolog** | `bash examples/prolog-proof-trees/run.sh` |
| Boolean compound check (do all five misconfigs co-occur?) | **PySAT** | `bash examples/sat-control-regression/run.sh` |
| Quantify exploitation probability | **Risk model** | `python3 examples/prism-risk-prioritization/risk_model.py` |
| Quantify attacker cost + remediation ROI | **Game theory** | `python3 examples/game-theory-cost/cost_model.py` |
| Measure drift margin from safe to unsafe | **TLA+ (Python BFS)** | `python3 examples/tlaplus-temporal-safety/temporal_check.py` |
| Run **every** engine across all fixtures | **comparison harness** | `bash examples/compare-engines/run.sh` |

## Cross-engine matrix (compact)

Vulnerable fixture (`before` / `writeup-config` / similar). Each
row is the headline cell from `multi-engine-results.md`; click
through for full per-fixture detail.

| Example | CEL | SMT | Soufflé | Risk | Game |
|---|---|---|---|---|---|
| [apigw-private-api-scoped-deny](apigw-private-api-scoped-deny/multi-engine-results.md) | 0 | sat | 0 anon, 0 total | P=0% | no-path |
| [cloudtrail-stop-logging](cloudtrail-stop-logging/multi-engine-results.md) | 1 | sat (some) | 0 anon, 0 total | P=0% | no-path |
| [cognito-no-mfa-advanced-security](cognito-no-mfa-advanced-security/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [cognito-self-register-to-aws-creds](cognito-self-register-to-aws-creds/multi-engine-results.md) | 1 | sat | 12 anon, 42 total | P=41% | $300 |
| [eks-aws-auth-template-injection](eks-aws-auth-template-injection/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [eks-rbac-webhook-config-access](eks-rbac-webhook-config-access/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [iam-21-privesc-5-patterns](iam-21-privesc-5-patterns/multi-engine-results.md) | 1 | sat | 0 anon, 58 total | P=0% | $1100 |
| [iam-attach-user-policy-self](iam-attach-user-policy-self/multi-engine-results.md) | 1 | sat | 0 anon, 3 total | P=0% | no-path |
| [iam-autoscaling-privesc-bypass](iam-autoscaling-privesc-bypass/multi-engine-results.md) | 1 | sat | 0 anon, 19 total | P=40% | $900 |
| [iam-multi-hop-trust](iam-multi-hop-trust/multi-engine-results.md) | 0 | sat | 0 anon, 10 total | P=73% | $2300 |
| [iam-overpermission-wildcard](iam-overpermission-wildcard/multi-engine-results.md) | 1 | sat (some) | 0 anon, 8 total | P=65% | $900 |
| [s3-broad-write-scope](s3-broad-write-scope/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-bucket-name-dangling](s3-bucket-name-dangling/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-cross-account-replication-overperm](s3-cross-account-replication-overperm/multi-engine-results.md) | 0 | sat | 0 anon, 45 total | P=0% | no-path |
| [s3-dotgit-readable](s3-dotgit-readable/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-public-list-policy](s3-public-list-policy/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-public-read-policy](s3-public-read-policy/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-tenant-prefix-isolation](s3-tenant-prefix-isolation/multi-engine-results.md) | 1 | — | 0 anon, 0 total | P=0% | no-path |
| [sns-secrets-compound-chain](sns-secrets-compound-chain/multi-engine-results.md) | 0 | sat | 0 anon, 10 total | P=0% | no-path |
| [staging-stale-endpoint](staging-stale-endpoint/multi-engine-results.md) | 2 | — | 0 anon, 0 total | P=0% | no-path |

## Quick Start for Your Own Environment

1. Pick the scenario closest to your concern from the
   pattern groups above.
2. Read its `multi-engine-results.md` to see which engines
   speak about that scenario shape.
3. Replace the bundled `fixtures/<phase>/observations/`
   with your own observation snapshots (extracted via the
   companion `stave-extractor` tooling or hand-authored).
4. Re-run: `bash run.sh` from the example's directory, or
   point the comparison harness at all engines: `bash
   examples/compare-engines/run.sh`.
5. If a particular engine returns empty / `n/a` on your
   fixture, that is documented in the `multi-engine-results.md`
   for the matched example — it's an engine-rule gap, not a
   Stave bug.

## Engine coverage summary

| Engine | Useful | Empty / no-signal | n/a / skipped | Error |
|---|---:|---:|---:|---:|
| cel | 18 | 31 | 0 | 0 |
| souffle | 49 | 0 | 0 | 0 |
| clingo | 3 | 46 | 0 | 0 |
| prolog | 4 | 45 | 0 | 0 |
| pysat | 0 | 49 | 0 | 0 |
| risk | 6 | 43 | 0 | 0 |
| tla | 6 | 43 | 0 | 0 |
| game | 7 | 42 | 0 | 0 |

*Useful* counts cells that surfaced a positive signal
(non-zero finding count, sat verdict, non-trivial
reachability count, P > 0, named compound, etc.).
*Empty / no-signal* counts engine cells that ran but
returned no actionable data — usually because the
fixture is a remediated counterpart or because the
engine's rule program does not have rules for the
fixture's predicate shape.

Regenerate this catalog with `python3 scripts/h1-matrix/run.py`
followed by `python3 scripts/h1-matrix/render.py` (see
[`scripts/h1-matrix/README.md`](../scripts/h1-matrix/README.md)).

## Lineage: H1 vs InfoSec writeup origins

The 20 scenarios above came from two streams of work:

- **H1 / HackerOne validation** — each scenario reverse-engineers
  a published HackerOne disclosure or technique to demonstrate
  what Stave detects on the same configuration shape.
- **InfoSec writeup iterations** — Iter 11 through Iter 16 plus
  the Ext A / Ext B / iter-15-ext extensions. Each iteration
  produced a fixture pair, the corresponding control(s), and a
  Dev.to article (`channels/devto/<scenario>.md`).

[`INFOSEC-VALIDATION.md`](INFOSEC-VALIDATION.md) maps each
InfoSec iteration to its on-disk example directory.

## SMT query coverage

**18 of 20** scenarios have a paired `query.smt2` after PR 5
(resource-policy Principal/Action projector) landed. The 2
remaining gaps are not projector-blocked — they're query-shape
gaps:

- `s3-tenant-prefix-isolation` — discriminator is a structured
  string (`signs_uploads;enforce_prefix=true;allow_traversal=false`)
  inside a single property; needs either a substring-extracting
  projector or a query-side string-equality match.
- `staging-stale-endpoint` — four fixtures modeling distinct
  states rather than a vulnerable/remediated pair; the matrix
  harness needs explicit pair selection per query.

18/20 is the practical ceiling without substring SMT theory
queries or matrix tooling changes. See
[`SMT-QUERY-GAPS.md`](SMT-QUERY-GAPS.md) for the per-fixture
rationale and the projector-to-fixture mapping.
