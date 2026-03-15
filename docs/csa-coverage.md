# CSA Cloud Security Lessons Coverage

How Stave addresses the 7 cloud security lessons from the Cloud Security Alliance article [7 Cloud Security Lessons from the AWS Crypto Mining Campaign](https://cloudsecurityalliance.org/blog/2026/03/09/7-cloud-security-lessons-from-the-aws-crypto-mining-campaign) (March 2026).

## Lesson 1: Compromised credentials create immediate damage

**The problem:** Attackers obtained valid credentials and used them to access the environment legitimately. Stolen or misused credentials can be more dangerous than software flaws.

**How Stave helps:** Stave detects the configuration gaps that make credential theft exploitable. If a bucket has no Public Access Block, overly broad IAM policies, or public ACL grants, Stave flags these before credentials are stolen. An attacker with credentials can't exfiltrate data from a bucket that was already locked down.

**Controls:** `CTL.S3.CONTROLS.001` (Public Access Block), `CTL.S3.ACCESS.001` (cross-account access), `CTL.S3.ACCESS.002` (wildcard action policies).

## Lesson 2: Attack speed outpaces response timelines

**The problem:** Crypto mining workloads began within minutes of credential compromise. Traditional alerting required hours or days to trigger.

**How Stave helps:** Stave shifts detection left — it finds unsafe state before the incident. Running offline against snapshots in CI means that by the time an attacker arrives, the misconfiguration they'd exploit has already been flagged and remediated. You don't need to detect the attack in real-time if the attack surface doesn't exist.

**Workflow:** `stave apply` runs in CI on every snapshot. `ci gate` fails the pipeline if new violations appear.

## Lesson 3: Cloud abuse signals deeper security gaps

**The problem:** Organizations treated crypto mining as a cost issue rather than recognizing it as evidence of compromised access and potential persistence mechanisms.

**How Stave helps:** Stave proves those gaps exist with duration tracking. `--max-unsafe 168h` means "this bucket has been misconfigured for over 7 days." That's not an alert — it's evidence of a structural gap. A bucket that's been public for months is a different risk than one that was public for 5 minutes during a deploy.

**Controls:** Every control tracks unsafe duration. `stave diagnose` explains why a finding triggered and for how long.

## Lesson 4: Configuration changes complicate recovery

**The problem:** Attackers made subtle configuration modifications to slow containment. Organizations lacked visibility into what changed.

**How Stave helps:** Stave maintains configuration baselines via snapshots. `snapshot diff` shows exactly what changed between two points in time. `ci baseline` + `ci diff` detect new findings introduced by configuration drift. If an attacker weakens a security control, the next evaluation catches it.

**Workflow:** `stave snapshot diff --before snap-01.json --after snap-02.json` reveals field-level changes. `stave ci diff --before baseline.json --after evaluation.json` reports new, resolved, and unchanged findings.

## Lesson 5: Legitimate services enable malicious purposes

**The problem:** Attackers leveraged standard AWS services for unintended purposes. Organizations failed to restrict which services could be provisioned.

**How Stave helps:** Stave enforces least-privilege at the bucket level. Controls restrict what legitimate services and principals can do — before an attacker repurposes them.

**Controls:** `CTL.S3.ACCESS.002` (no wildcard action policies), `CTL.S3.ACCESS.003` (no external write access), `CTL.S3.AUTH.WRITE.001` (no authenticated-users write), `CTL.S3.ACL.ESCALATION.001` (no public ACL modification).

## Lesson 6: Disconnected signals create detection blind spots

**The problem:** The campaign became visible only when multiple warning signs were evaluated together. Organizations maintained fragmented monitoring across separate tools, preventing correlation.

**How Stave helps:** A single `stave apply` evaluates 43 controls together in one pass, correlating ACL state, bucket policy, Public Access Block, encryption, logging, versioning, and data classification for every bucket simultaneously. Stave doesn't have the fragmented-tools problem because it evaluates all signals in one engine against one observation set.

**Controls:** All 43 built-in S3 controls are evaluated in a single invocation. Findings reference each other through shared asset IDs.

## Lesson 7: Prevention requires understanding current exposure

**The problem:** Cloud environments evolve continuously. Without continuous visibility, risk accumulates quietly.

**How Stave helps:** Continuous exposure assessment via snapshot cadence. `snapshot quality` detects staleness and cadence gaps. `snapshot upcoming` shows what's approaching retention deadlines. The CI pipeline runs `stave apply` on every new snapshot, so risk accumulation is visible — not quiet.

**Workflow:** Capture snapshots on a regular cadence (daily or weekly). Run `stave apply` in CI. `stave status` shows when the last evaluation ran and what to do next.

## What Stave does not cover

Stave is the configuration safety layer. It does not cover:

- **Real-time credential monitoring** — use AWS GuardDuty or CloudTrail anomaly detection
- **Cost anomaly detection** — use AWS Cost Anomaly Detection
- **Runtime agent-based detection** — use CSPM agents or EDR tools
- **Live API querying** — Stave evaluates offline against snapshots, not live infrastructure

Stave's role is to prove that your infrastructure's configuration doesn't have the gaps that make these attacks possible in the first place. It complements runtime detection tools by ensuring the attack surface is minimized before an attacker arrives.
