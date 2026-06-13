# Stave Examples Catalog

**115 fixture pairs** across
**48 example scenarios**, each tested
against every available reasoning engine.

Every scenario ships a vulnerable fixture and a remediated
fixture. The matrix below shows what each engine reveals.
Pick the scenario closest to your environment and adapt it.

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

### Other

- **[ai-shadow-and-ghosts](ai-shadow-and-ghosts/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[bedrock-agent-overpermissioned](bedrock-agent-overpermissioned/multi-engine-results.md)** — 3 fixture(s): partial-remediation, remediated-config, writeup-config.
- **[bedrock-agent-tool-phi](bedrock-agent-tool-phi/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[bedrock-rag-phi-exposure](bedrock-rag-phi-exposure/multi-engine-results.md)** — 3 fixture(s): remediated-config, training-crossaccount, writeup-config.
- **[cognito-advsec-tristate](cognito-advsec-tristate/multi-engine-results.md)** — 3 fixture(s): audit-mode, enforced-mode, off-mode.
- **[cognito-iteration1-ghosts](cognito-iteration1-ghosts/multi-engine-results.md)** — 3 fixture(s): authflow-gap-config, remediated-config, writeup-config.
- **[cognito-iteration10-tokenuicompliance](cognito-iteration10-tokenuicompliance/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-iteration2-unauth](cognito-iteration2-unauth/multi-engine-results.md)** — 3 fixture(s): cross-resource-config, remediated-config, writeup-config.
- **[cognito-iteration3-authbaseline](cognito-iteration3-authbaseline/multi-engine-results.md)** — 3 fixture(s): recovery-bypass-config, remediated-config, writeup-config.
- **[cognito-iteration4-clientconfig](cognito-iteration4-clientconfig/multi-engine-results.md)** — 3 fixture(s): open-redirect-config, remediated-config, writeup-config.
- **[cognito-iteration5-authrole](cognito-iteration5-authrole/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-iteration6-advsec](cognito-iteration6-advsec/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-iteration7-federation](cognito-iteration7-federation/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-iteration8-monitoring](cognito-iteration8-monitoring/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-iteration9-orphans](cognito-iteration9-orphans/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[cognito-presignup-ghost](cognito-presignup-ghost/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[demo-ai-security](demo-ai-security/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[ecs-ssrf-credential-theft](ecs-ssrf-credential-theft/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[iam-cred-ttl-exceeded](iam-cred-ttl-exceeded/multi-engine-results.md)** — 3 fixture(s): no-expiry, ttl-exceeded, ttl-valid.
- **[imds-ssrf-chain](imds-ssrf-chain/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[meta-observation-stale](meta-observation-stale/multi-engine-results.md)** — 3 fixture(s): boundary, fresh, stale.
- **[s3-delegation-failure](s3-delegation-failure/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[sagemaker-execution-role-overprivileged](sagemaker-execution-role-overprivileged/multi-engine-results.md)** — 3 fixture(s): partial-remediation, remediated-config, writeup-config.
- **[sagemaker-notebook-prod-escape](sagemaker-notebook-prod-escape/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[shadow-admin-detection](shadow-admin-detection/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[shadow-ec2-lateral-movement](shadow-ec2-lateral-movement/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[vpc-peering-exfiltration](vpc-peering-exfiltration/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.
- **[z3-forbidden-state](z3-forbidden-state/multi-engine-results.md)** — 2 fixture(s): remediated-config, writeup-config.

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
| [ai-shadow-and-ghosts](ai-shadow-and-ghosts/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [apigw-private-api-scoped-deny](apigw-private-api-scoped-deny/multi-engine-results.md) | 0 | sat | 0 anon, 0 total | P=0% | no-path |
| [bedrock-agent-overpermissioned](bedrock-agent-overpermissioned/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [bedrock-agent-tool-phi](bedrock-agent-tool-phi/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [bedrock-rag-phi-exposure](bedrock-rag-phi-exposure/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cloudtrail-stop-logging](cloudtrail-stop-logging/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [cognito-advsec-tristate](cognito-advsec-tristate/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration1-ghosts](cognito-iteration1-ghosts/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration10-tokenuicompliance](cognito-iteration10-tokenuicompliance/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration2-unauth](cognito-iteration2-unauth/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration3-authbaseline](cognito-iteration3-authbaseline/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration4-clientconfig](cognito-iteration4-clientconfig/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration5-authrole](cognito-iteration5-authrole/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration6-advsec](cognito-iteration6-advsec/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration7-federation](cognito-iteration7-federation/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration8-monitoring](cognito-iteration8-monitoring/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-iteration9-orphans](cognito-iteration9-orphans/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-no-mfa-advanced-security](cognito-no-mfa-advanced-security/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [cognito-presignup-ghost](cognito-presignup-ghost/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [cognito-self-register-to-aws-creds](cognito-self-register-to-aws-creds/multi-engine-results.md) | 1 | sat | 12 anon, 42 total | P=41% | $300 |
| [demo-ai-security](demo-ai-security/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [ecs-ssrf-credential-theft](ecs-ssrf-credential-theft/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [eks-aws-auth-template-injection](eks-aws-auth-template-injection/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [eks-rbac-webhook-config-access](eks-rbac-webhook-config-access/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [iam-21-privesc-5-patterns](iam-21-privesc-5-patterns/multi-engine-results.md) | 1 | sat | 0 anon, 58 total | P=0% | $1100 |
| [iam-attach-user-policy-self](iam-attach-user-policy-self/multi-engine-results.md) | 1 | sat | 0 anon, 3 total | P=0% | no-path |
| [iam-autoscaling-privesc-bypass](iam-autoscaling-privesc-bypass/multi-engine-results.md) | 1 | sat | 0 anon, 19 total | P=40% | $900 |
| [iam-cred-ttl-exceeded](iam-cred-ttl-exceeded/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [iam-multi-hop-trust](iam-multi-hop-trust/multi-engine-results.md) | 0 | sat | 0 anon, 6 total | P=40% | $1500 |
| [iam-overpermission-wildcard](iam-overpermission-wildcard/multi-engine-results.md) | 1 | sat | 0 anon, 8 total | P=65% | $900 |
| [imds-ssrf-chain](imds-ssrf-chain/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [meta-observation-stale](meta-observation-stale/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [s3-broad-write-scope](s3-broad-write-scope/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-bucket-name-dangling](s3-bucket-name-dangling/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-cross-account-replication-overperm](s3-cross-account-replication-overperm/multi-engine-results.md) | 0 | sat | 0 anon, 45 total | P=0% | no-path |
| [s3-delegation-failure](s3-delegation-failure/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [s3-dotgit-readable](s3-dotgit-readable/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-public-list-policy](s3-public-list-policy/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-public-read-policy](s3-public-read-policy/multi-engine-results.md) | 1 | sat | 0 anon, 0 total | P=0% | no-path |
| [s3-tenant-prefix-isolation](s3-tenant-prefix-isolation/multi-engine-results.md) | 1 | — | 0 anon, 0 total | P=0% | no-path |
| [sagemaker-execution-role-overprivileged](sagemaker-execution-role-overprivileged/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [sagemaker-notebook-prod-escape](sagemaker-notebook-prod-escape/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [shadow-admin-detection](shadow-admin-detection/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [shadow-ec2-lateral-movement](shadow-ec2-lateral-movement/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [sns-secrets-compound-chain](sns-secrets-compound-chain/multi-engine-results.md) | 0 | sat | 0 anon, 18 total | P=0% | no-path |
| [staging-stale-endpoint](staging-stale-endpoint/multi-engine-results.md) | 2 | — | 0 anon, 0 total | P=0% | no-path |
| [vpc-peering-exfiltration](vpc-peering-exfiltration/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |
| [z3-forbidden-state](z3-forbidden-state/multi-engine-results.md) | 0 | — | 0 anon, 0 total | P=0% | no-path |

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
| cel | 18 | 97 | 0 | 0 |
| souffle | 115 | 0 | 0 | 0 |
| clingo | 27 | 88 | 0 | 0 |
| prolog | 28 | 87 | 0 | 0 |
| pysat | 8 | 107 | 0 | 0 |
| risk | 7 | 108 | 0 | 0 |
| tla | 6 | 109 | 0 | 0 |
| game | 8 | 107 | 0 | 0 |

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
