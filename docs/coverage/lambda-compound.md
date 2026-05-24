# Lambda compound coverage map

Maps the AWS compound control authoring plan's Phase 5 (Lambda) 4
sub-families against existing Stave controls and chains.

## Headline finding

Lambda has **58 atomic controls and 0 compound-scope controls
today** per the classifier. Lambda observations are per-function
(`compute.kind`, `compute.function`, `compute.function_url`, etc.)
— no cross-asset prefix in the predicate AST.

**The Lambda compound surface lives in 27 chains today** (with
this commit, 28). Representative:

- `chains/lambda_total_compromise.yaml`
- `chains/lambda_public_exposure.yaml`
- `chains/lambda_public_ddos.yaml`
- `chains/lambda_blind_execution.yaml`
- `chains/lambda_confused_deputy.yaml`
- `chains/lambda_credential_exposure.yaml`
- `chains/lambda_credential_history.yaml`
- `chains/lambda_dormant_risk.yaml`
- `chains/lambda_event_loss.yaml`
- `chains/lambda_exfiltration_bridge.yaml`
- `chains/lambda_ghost_cascade.yaml`
- `chains/lambda_invocation_sprawl.yaml`
- `chains/lambda_lifecycle_debris.yaml`
- `chains/lambda_logging_blind.yaml`
- `chains/lambda_monitoring_gap.yaml`
- (+ 12 more cross-service)

## Plan sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Execution role + resource policy + event source mapping | covered | `lambda_confused_deputy` (TRIGGER.CONFUSEDDEPUTY + POLICY.CROSSACCOUNT), `lambda_total_compromise` |
| 2 | VPC attachment + execution role + accessed resources | partial | `lambda_credential_exposure` covers role + secrets aspect; explicit VPC-attachment + role-reach chain is a follow-up gap |
| 3 | Layer + function permission composition | covered (this commit) | **NEW** `lambda_layer_supply_chain_compromise` (LAYER.SECRETS + LAYER.GHOST + LAYER.ORIGIN) |
| 4 | Async destination + invocation permission | covered | `lambda_event_loss` (DLQ.MISSING + ESM.NODLQ + GHOST.DLQ), `lambda_invocation_sprawl` |

**Summary:** 3 covered, 1 partial, 0 gap.

## What this commit ships for Lambda

- **1 net-new chain:** `chains/lambda_layer_supply_chain_compromise.yaml`
  (sub-family 3 — LAYER.SECRETS + LAYER.GHOST + LAYER.ORIGIN
  conjunction). Threshold 2; severity high; preconditions
  container_code_execution; postconditions iam_credential_theft.

## Why ~20 net-new wasn't the right target

Lambda already has 27 chains substantiating compound risk across
3 of 4 sub-families. Sub-family 2 (VPC attachment + role reach)
is one chain away from covered — adding it is a future Lambda-
followup commit.

## Notes for follow-up

- **Sub-family 2 (VPC + role reach):** worth one explicit chain
  composing function VPC-attachment with the role's reachable
  resources outside the VPC (e.g., function in VPC X with role
  reaching S3 buckets in VPC Y via VPC endpoint policy). Member
  controls exist in `controls/lambda/network/` and
  `controls/iam/identity/BLASTRADIUS*`; the chain itself isn't
  yet authored.
- **Compound-share trajectory:** unchanged at 6.77%
  (chains aren't classifier-counted). Lambda chain count
  27 → 28 with this commit.
