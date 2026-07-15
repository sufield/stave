# What Stave Finds

This is real output from `stave apply` against a deliberately
misconfigured AWS environment — a Bedrock AI agent with
overpermissioned IAM roles, unencrypted patient data, and missing
monitoring. Nothing is running. This is what the tool produces.

## The output

```
Evaluation Results
==================

Run: 2026-05-10 00:00:00 UTC (max-unsafe: 7d, snapshots: 1)

Summary
-------
  Assets evaluated:    4
  Attack surface:      4
  Violations:          109
  Issues (consolidated): 101

Findings
--------
  #    Severity   MITRE        Control                                  Asset
  1    high                    AGENT.GUARDRAIL.001                      CUSTSUPPORTAGENT
  2    high                    AGENT.LOGGING.001                        CUSTSUPPORTAGENT
  3    high                    AGENT.OVERPERM.LAMBDA.001                CUSTSUPPORTAGENT
  4    high                    MONITOR.ASSUMEROLE.001                   CUSTSUPPORTAGENT
  ...
  24   high                    OVERPERM.S3PHI.001                       patient-lookup-tool
  25   high                    AGENT.OVERPERM.S3.001                    CUSTSUPPORTAGENT
  ...
  58   high                    ENCRYPT.003                              patient-records
  59   high                    ENCRYPT.004                              patient-records
  60   high                    OWNERSHIP.001                            patient-records
  61   medium                  MONITOR.ACCESSKEY.001                    CUSTSUPPORTAGENT
  ...
  105  medium                  LIFECYCLE.MULTIPART.001                  patient-records
  106  low                     MONITOR.TRAIL.ACCESS.001                 CUSTSUPPORTAGENT
  ...
  109  low                     MONITOR.TRAIL.ACCESS.001                 patient-records

Compound Chains: 11
  [critical] bedrock_agent_overpermissioned
  [critical] bedrock_agent_tool_phi_exposure
  [critical] bedrock_rag_phi_exposure
  [critical] iam_boundary_governance_failure  (x4 assets)
  [critical] iam_escalation_undetected  (x4 assets)

Near-Miss Chains: 59
  [critical] bedrock_agent_data_exfiltration — missing: CTL.BEDROCK.AGENT.GHOST.LAMBDA.001
  [critical] cognito_unauth_phi_s3 — missing: CTL.COGNITO.IDPOOL.UNAUTH.S3.001
  [critical] iam_condition_key_complexity — missing: CTL.IAM.POLICY.CONDITION.NOTRESOURCE.001
  [critical] iam_management_account_risk — missing: CTL.IAM.IDENTITY.ROOTACCOUNT.001
  [critical] identity_blast_radius — missing: CTL.IAM.IDENTITY.BLASTRADIUS.001
  [high] intent_expiry_unclassified_ai_datasource — missing: CTL.S3.CLASSIFY.COVERAGE.001
  [critical] persistent_identity_creation — missing: CTL.IAM.ADMIN.COUNT.001
  ...

Run with --verbose for full evidence, reasoning, and remediation.
```

## Reading the output

### Compound chains — every precondition is present

```
Compound Chains: 11
  [critical] bedrock_agent_overpermissioned
  [critical] bedrock_agent_tool_phi_exposure
  [critical] bedrock_rag_phi_exposure
```

These are not individual misconfigurations. Each compound chain
represents a multi-step attack path where every prerequisite is
satisfied. `bedrock_agent_tool_phi_exposure` means: the agent has
a tool (`patient-lookup-tool`) with access to a PHI data source
(`patient-records`), the tool's Lambda role is overpermissioned,
and there's no guardrail constraining what the agent can ask for.
The path from "ask the agent a question" to "exfiltrate patient
records" is open. Fix these first.

### Near-miss chains — one configuration change away

```
Near-Miss Chains: 59
  [critical] bedrock_agent_data_exfiltration — missing: CTL.BEDROCK.AGENT.GHOST.LAMBDA.001
```

One precondition in the attack chain is not yet present. The
`missing:` field names the control that would need to fail for
the chain to become exploitable. This is a leading indicator:
protect the named control. If `BEDROCK.AGENT.GHOST.LAMBDA.001`
starts failing (someone adds an unmonitored Lambda to the agent),
this near-miss becomes a compound chain — the path opens.

### Standard findings — true misconfigurations

```
  58   high                    ENCRYPT.003                              patient-records
  59   high                    ENCRYPT.004                              patient-records
  60   high                    OWNERSHIP.001                            patient-records
```

Individual control violations without a connected attack path.
`ENCRYPT.003` on `patient-records` means the S3 bucket holding
patient data lacks server-side encryption. Real misconfiguration,
real fix needed — but no compound chain amplifies it (yet).

### What's not in the output

109 violations, 4 assets. If this environment had a fifth asset
that passed every control, it would not appear in the findings.
A clean result is a deliverable — it means the controls were
evaluated and the configuration is compliant. Stave reports
what it verified, not just what it found.

## Try it yourself

```bash
# Docker (zero install)
docker run --rm ghcr.io/sufield/stave-demo

# Or install and run
go install github.com/sufield/stave/cmd/stave@latest
stave apply --observations ./examples/demo-ai-security/fixtures/writeup-config/observations \
  --eval-time 2026-05-10T00:00:00Z
```

## Regeneration

This page shows output from the `demo-ai-security` fixture.
Regenerate after release if controls, chains, or output format
changed:

```bash
stave apply \
  --observations examples/demo-ai-security/fixtures/writeup-config/observations \
  --eval-time 2026-05-10T00:00:00Z
```
