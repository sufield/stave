# Identity Blast Radius

Identity blast radius answers: "If this credential is compromised,
how many resources can the attacker reach?"

Unlike control-level blast radius (which measures how disabling a
control blinds the account), identity blast radius measures the
**damage surface** of a single compromised credential. A role that
can reach 80 resources across 3 accounts is a different risk than
a role scoped to 5 resources in one account — even if both roles
have the same severity-level findings.

## How it works

### Extractor computes, Stave evaluates

Stave does not traverse IAM policy graphs. The extractor performs
the analysis and stores the results as observation properties:

```
Extractor                              Stave
────────                              ─────
Traverse sts:AssumeRole edges    →    Check reachable_resources_count > 50
Collect data access permissions  →    Check blast_radius_scope == "cross_account"
Count unique resources/accounts  →    Check assume_chain_depth > 2
Store in observation properties  →    Evaluate as standard predicates
```

This preserves Stave's core promise: deterministic evaluation of
YAML controls against observation properties. No graph engine in
the CLI.

### Observation properties

The extractor populates these fields on each IAM role:

```yaml
properties:
  identity:
    kind: role
    role:
      reachable_resources_count: 47    # total unique resources accessible
      reachable_accounts_count: 3      # AWS accounts reachable via assume chains
      assume_chain_depth: 2            # longest sts:AssumeRole chain
      blast_radius_scope: cross_account # account | cross_account
```

### Extractor analysis steps

1. For each IAM role, list attached and inline policies
2. Parse policy documents for `sts:AssumeRole` with Resource ARNs
3. For each assumable role, recursively collect its permissions
4. Count unique resource ARNs across all reachable roles
5. Count unique account IDs from resource ARNs
6. Measure the longest assumption chain depth
7. Classify scope: `cross_account` if any resource is in another account

## Controls

### CTL.IAM.IDENTITY.BLASTRADIUS.001 — Resource threshold

```
Fires when: reachable_resources_count > 50
Severity: high
```

A single role that can reach more than 50 resources has a wide blast
radius. Credential compromise gives an attacker a large surface area.

**Remediation:** Split broad roles into per-service roles with scoped
Resource ARNs. Use IAM Access Analyzer to identify unused permissions.

### CTL.IAM.IDENTITY.BLASTRADIUS.002 — Cross-account without external ID

```
Fires when: blast_radius_scope == "cross_account"
        AND cross_account_trust_without_external_id == true
Severity: critical
```

This is the maximum blast radius configuration: the role can reach
resources across multiple AWS accounts AND anyone in the trusted
account can assume it (no external ID barrier).

**Remediation:** Add `sts:ExternalId` condition to the trust policy.
Restrict trust to specific role ARNs, not account-wide principals.

### CTL.IAM.IDENTITY.BLASTRADIUS.003 — Assume chain depth

```
Fires when: assume_chain_depth > 2
Severity: medium
```

Deep assumption chains (A → B → C → D) create hidden transitive
access that is difficult to audit. Each hop potentially widens the
blast radius beyond what was intended for the originating role.

**Remediation:** Flatten the chain. Grant permissions directly to the
role that needs them rather than chaining through intermediates.

## Safety chain: identity_blast_radius

The three blast radius controls participate in a compound chain
together with credential protection controls:

```yaml
id: identity_blast_radius
controls:
  - CTL.IAM.IDENTITY.BLASTRADIUS.001  # wide reach
  - CTL.IAM.MFA.HWKEY.001             # no hardware MFA
  - CTL.IAM.CRED.EXPIRY.001           # no credential TTL
  - CTL.IAM.POLICY.SOD.001            # data + IAM combined
escalation_threshold: 2
compound_severity: critical
```

When a role has wide blast radius AND lacks credential protections,
the compound finding fires: "If this credential is stolen, the
attacker reaches many resources with no time-based or identity-based
barrier."

## Example output

### JSON

```json
{
  "chain_findings": [{
    "chain": "identity_blast_radius",
    "controls_failing": [
      "CTL.IAM.IDENTITY.BLASTRADIUS.001",
      "CTL.IAM.CRED.EXPIRY.001"
    ],
    "missing_safeguards": [
      "CTL.IAM.MFA.HWKEY.001",
      "CTL.IAM.POLICY.SOD.001"
    ],
    "compound_score": 36.0,
    "severity": "CRITICAL",
    "narrative": "Identity with wide blast radius and weak protections..."
  }]
}
```

### Text

```
Compound Risk Chains
--------------------

  [CRITICAL] Chain: identity_blast_radius
  Identity with wide blast radius and weak protections.
  Failing:    CTL.IAM.IDENTITY.BLASTRADIUS.001, CTL.IAM.CRED.EXPIRY.001
  Fix any of: CTL.IAM.MFA.HWKEY.001, CTL.IAM.POLICY.SOD.001
  Score:      36.0
  Stages:     persistence
```

"Fix any of" shows the cheapest remediation: enabling hardware MFA
or enforcing separation of duties would break the chain below its
escalation threshold.

## Relationship to control-level blast radius

Stave has two kinds of blast radius:

| Type | What it measures | Where it's stored |
|---|---|---|
| **Control blast radius** | How far damage spreads when a *control* fails | Control `params.blast_radius` |
| **Identity blast radius** | How far damage spreads when a *credential* is compromised | Observation `identity.role.*` properties |

Control blast radius multiplies compound scores (e.g., disabled
CloudTrail inflates all findings by 2.5x). Identity blast radius
triggers its own controls when thresholds are exceeded.

Both feed into the risk reasoning engine — control blast radius
through the multiplier, identity blast radius through the chain.

## Key files

| File | Purpose |
|---|---|
| `controls/iam/identity/CTL.IAM.IDENTITY.BLASTRADIUS.001-003.yaml` | 3 blast radius controls |
| `chains/identity_blast_radius.yaml` | Compound chain definition |
| `aws-lab/scripts/exp73-iam-identity-blast-radius.sh` | Extractor pattern for computing reachable resources |
| `docs/blast-radius.md` | Control-level blast radius documentation |
