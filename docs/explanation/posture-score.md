# Posture Score

What the 0-100 score measures, how it is computed, and what it does not tell you.

---

## What the Score Measures

The posture score is a single number representing the current state of security configuration compliance. It answers one question: "how well are we maintaining our security invariants right now?"

A score of 81 does not mean "we are 81% secure." Security is not a percentage. The score measures *compliance with defined invariants* — the gap between what the controls require and what the infrastructure provides.

## Four Dimensions

The score is a weighted combination of four independent dimensions:

| Dimension | Weight | Measures |
|-----------|--------|----------|
| Severity | 45% | Distribution of open violations by severity |
| SLA | 25% | Fraction of findings remediated within SLA deadlines |
| Chain | 20% | Compound risk — whether multi-control attack paths are active |
| Coverage | 10% | Fraction of the control catalog that is evaluable |

### Severity (45%)

The severity dimension penalizes critical and high violations more heavily than medium and low. One critical finding has more impact on the score than ten low findings. This prevents score gaming by fixing only easy low-severity items.

### SLA (25%)

The SLA dimension measures whether the organization is remediating within its defined deadlines. Without an SLA policy (`stave sla init`), this dimension scores 0 — the most impactful single action a new user can take is generating an SLA policy.

### Chain (20%)

The chain dimension measures compound risk. A single failing control is one thing. Three failing controls that together form a complete attack path — from internet access to credential theft to data exfiltration — is qualitatively worse. Active chains depress this dimension.

### Coverage (10%)

The coverage dimension measures how much of the control catalog can evaluate against the current snapshot. Controls that cannot evaluate (because the snapshot lacks the required properties) contribute nothing to the assessment — they are blind spots.

## Bands

| Band | Score | Description |
|------|-------|-------------|
| CRITICAL | < 40 | Immediate executive escalation required |
| POOR | 40-59 | Significant risk, remediation plan required |
| FAIR | 60-69 | Moderate risk, active improvement needed |
| GOOD | 70-84 | Manageable risk, SLA compliance is key |
| STRONG | 85-94 | Strong posture, maintain vigilance |
| EXCELLENT | 95-100 | Exemplary posture |

## What the Score Does Not Tell You

The score does not tell you whether you will be breached. It does not predict the likelihood of an attack. It does not measure the skill of your security team.

The score tells you the gap between your defined security requirements and your current infrastructure state. A score of 95 in an organization with 10 controls means something different from 95 in an organization with 630 controls.

The score is most useful as a trend — is it improving, stable, or regressing? A score that improves from 72 to 81 over a quarter tells you more than the absolute number 81.
