# Time-Related Features — Audit

Stave's value proposition leans on time as a first-class dimension:
configuration **history** is what makes a "ghost reference" different
from a "reference," and **duration** is what distinguishes a benign
transient from a violation. Yesterday's `temporal-dimension.md` (at the
bizacademy root, commit `d27b7f748`) makes the argument explicitly:
single-snapshot scanners suffer from **amnesia** (no memory of
yesterday) and **the dice-roll problem** (inconsistency across runs).
Stave's response is a time model that's both **deterministic** (same
inputs → same outputs) and **historical** (snapshots indexed by
captured_at, traversable retroactively).

This document audits what's shipped, identifies gaps, and compares
each feature against the closest commercial equivalents.

## Gap table — at a glance

| # | Feature | Shipped? | Doc-vs-code parity | Gap class |
|---|---|---|---|---|
| 1 | `--max-unsafe` SLA window on `stave apply` | ✅ | ✓ matches | none |
| 2 | `first_unsafe_at` / `last_seen_unsafe_at` / `unsafe_duration_hours` on findings | ✅ | ✓ matches | none |
| 3 | `--now` override for deterministic time | ✅ | ✓ matches | none |
| 4 | `stave bisect` — find first-violation transition | ✅ | ✓ matches `docs/bisect-timeline.md` | none |
| 5 | Snapshot diff (`stave diff --snapshot-before/--snapshot-after`) | ✅ | ✓ matches — doc-name drift closed in Temporal Iteration 1 | ~~GAP-A~~ closed |
| 6 | `stave trend` — posture metrics across N assessments | ✅ | ✓ matches `docs/posture-trending.md` | none |
| 7 | `stave budget` — SLA burn-rate in a budget period | ✅ | ✓ matches | none |
| 8 | `stave watch` — continuous monitor of observation dir | ✅ | ✓ matches | none |
| 9 | `stave monitor` — live posture-score terminal display | ✅ | ✓ matches | none |
| 10 | Per-finding `HasTemporalEvidence` flag | ✅ | ✓ matches | none |
| 11 | Recurrence tracking across runs (`internal/core/evaluation/recurrence/`) | ✅ | partial — no user-facing command surfaces it | **GAP-B: surfacing** |
| 12 | Time-based predicate fields in 176 controls (`is_idle`, `is_dormant`, `appears_unused`, expiry-days, etc) | ✅ | ✓ matches per-control YAML | none |
| 12b | **Time-Bound Credential Invariant** — 48 controls: IAM credential TTL (10, includes the new TTL-elapsed variant), token TTL (5), cert/SAML expiry (11), AD/Azure/GCP lifecycle (11), Secrets Manager rotation (7), KMS rotation (3), Bedrock long-lived keys (1). 37 of the 48 carry NHI7 (Long-Lived Secrets) per [`docs/compliance/owasp-nhi-top10.md`](compliance/owasp-nhi-top10.md). Strategic framing in [`business/collins/first-10.md`](../../business/collins/first-10.md) lines 225/350/556 + the [time-adversary thesis](../../business/security-theory/time-adversary.md). | ✅ | ✓ matches catalog — stricter TTL-elapsed variant shipped as `CTL.IAM.CRED.TTL.EXCEEDED.001` (Temporal Iteration 2) | ~~GAP-L~~ closed |
| 13 | Temporal ghost detection — 2 controls confirm ghosts across two observations | ✅ | ✓ matches — dedicated doc at [`docs/temporal-ghost.md`](temporal-ghost.md) (closed in Temporal Iteration 1) | ~~GAP-C~~ closed |
| 14 | Exposure window tracking (`internal/core/asset/` close-on-secure semantics) | ✅ | ✓ matches | none |
| 15 | TLA+ temporal safety — drift margin from "safe today" to "unsafe in N flips" | ✅ | `examples/tlaplus-temporal-safety/` only | none |
| 16 | `examples/forecast/` — linear-trend posture-score projector | ✅ | external example only; no `stave forecast` subcommand wraps it | **GAP-D: cmd subsumption** |
| 17 | Severity-keyed SLA in compliance profiles | ✅ | ✓ default profile now applied when neither `--sla-profile` nor `--sla-profile-file` is set (Temporal Iteration 1, `internal/adapters/sla/provider.go`) | ~~GAP-E~~ closed |
| 18 | Observation freshness / extractor-staleness detection | ✅ | shipped as `CTL.META.OBSERVATION.STALE.001` (Temporal Iteration 2) — meta-control flags stale-collector facts via `properties.meta.observation.is_stale` | ~~GAP-F~~ closed |
| 19 | Intent-expiry tracking ("Monday OK, Tuesday intent vanished") | ❌ | `reviewed_at` is a remediation suggestion, not a predicate input | **GAP-G: missing feature** |
| 20 | Long-horizon causality ("this regression today was caused by IaC commit 6 months ago") | ❌ | bisect finds transition; doesn't attribute to a commit / actor / ticket | **GAP-H: scope boundary** |
| 21 | Silent-monitoring-collapse over time ("the dog that didn't bark") | partial | `chains/silent_monitoring_collapse.yaml` + `cloudwatch_silence_as_safety.yaml` detect missing alarms in the *current* state, not absence of expected alerting *events* over time | **GAP-I: deeper temporal modeling** |
| 22 | "Time travel" / "what did our posture look like on date X" reports | partial | `stave apply --now <past-date>` works for fixtures that include a snapshot from that date, but there's no point-in-time-report subcommand | **GAP-J: cmd composition** |
| 23 | Cross-control temporal compound ("control A failed first, then control B 7 days later") | ❌ | per-control temporal evidence exists; cross-control time-ordering doesn't compose into chains | **GAP-K: deeper compound** |

**As of Temporal Iteration 1 (closing commit):**
- ~~GAP-A~~ (docs `stave drift` → `stave diff` rename) — **closed**
- ~~GAP-C~~ (temporal-ghost dedicated doc) — **closed**, see [`docs/temporal-ghost.md`](temporal-ghost.md)
- ~~GAP-E~~ (severity-keyed SLA as default) — **closed**, embedded `default` profile auto-loaded
- **GAP-L** added — Time-Bound Credential Invariant stronger variant (row 12b)

**As of Temporal Iteration 2 (closing commit):**
- ~~GAP-F~~ (observation freshness) — **closed**, shipped as `CTL.META.OBSERVATION.STALE.001` (governance/NHI8, severity high)
- ~~GAP-L~~ (stricter TBCI variant) — **closed**, shipped as `CTL.IAM.CRED.TTL.EXCEEDED.001` (identity/NHI7, severity critical)

Remaining open: GAP-B (recurrence surfacing), GAP-D (`stave forecast`
subcommand), GAP-G (intent expiry), GAP-H (causality — out of
scope), GAP-I (silent-monitoring over time), GAP-J (time-travel
reports), GAP-K (cross-control temporal compound). Items B/D are
surfacing decisions; G/I/J/K are feature-extension scope; H is an
architectural boundary.

---

## Per-feature detail

Each section: what it is, how it's applied, the problem it addresses,
and how existing tools (commercial CSPM, AWS Config, CloudCustodian,
etc.) compare.

### 1. SLA window — `--max-unsafe`

**Description.** Every `stave apply` invocation declares a maximum
allowed unsafe duration (default from project config, override via
`--max-unsafe 168h` or per-severity via `--sla-profile`). A finding's
`unsafe_duration_hours` is compared against the SLA; exceeding it
drives the finding's severity and the run's exit code.

**Applied as.** Per-control predicate evaluation produces a violation;
the temporal evidence (`first_unsafe_at` → `now`) measures duration;
the SLA window decides whether duration converts the finding into a
gate-failing violation (exit 3).

**Problem addressed.** "An unsafe configuration that lasted 5 minutes
during a deployment window is not the same as one that's been unsafe
for 90 days." The SLA window is the time-aware threshold that
distinguishes transient operational drift from genuine posture decay.

**Existing tools.** AWS Config conformance packs have remediation
SLAs but they're enforcement-side, not detection-side. Wiz's compliance
posture has an SLA dashboard but it's per-finding, not control-level.
CloudCustodian has `mark-for-op` + `op` patterns that approximate SLA
but require explicit two-policy authoring.

---

### 2. Per-finding temporal evidence — `first_unsafe_at`, `last_seen_unsafe_at`, `unsafe_duration_hours`

**Description.** Every finding's `evidence` block carries the
timestamps that bracket the violation: when it first appeared
(`first_unsafe_at`), when it was most recently observed
(`last_seen_unsafe_at`), and the elapsed duration. These come from
walking the snapshot archive and finding the earliest snapshot where
the predicate fires.

**Applied as.** Encoded directly in the `out.v0.1` schema. Downstream
consumers (the encoding verifier, the SARIF exporter, evidence
archives) preserve these fields end-to-end.

**Problem addressed.** Forensic question: "When did this start?" An
auditor or incident responder reading a finding sees the elapsed time
without needing to cross-reference CloudTrail.

**Existing tools.** AWS Config has the closest equivalent —
ConfigurationItem timestamps and config history retention — but
querying "when did this control transition to non-compliant" requires
DSL joins or a custom Lambda. Wiz exposes "first detected" /
"last seen" on findings; closest commercial peer.

---

### 3. Deterministic `--now` override

**Description.** Every command that consults "current time" accepts
`--now <RFC3339>` to override. Tests and CI pipelines use it for
reproducibility; the same snapshot + same `--now` produces the same
output, every run.

**Applied as.** Threaded through the engine via `internal/platform/state`
and the SLA evaluator. The unit-test stub clock is repaired in
`666dd4ff2` to ensure `--now` semantics match wall-clock semantics.

**Problem addressed.** The "dice-roll problem" from the temporal-
dimension argument: AI scanners produce different verdicts on identical
input because they're nondeterministic. Stave answers "same input →
same output, today and a year from now" — which makes long-running
audit evidence trustworthy.

**Existing tools.** Most security scanners are inherently
nondeterministic (live API calls, model probabilities). Open Policy
Agent / Rego shares this property because policy is pure. CSPM tools
generally don't expose a "freeze the clock for replay" knob.

---

### 4. `stave bisect` — first-violation transition search

**Description.** Binary-search the snapshot archive for the
transition into the current violation window. `stave bisect
--observations <archive> --control-id CTL.X.Y.001` returns the pair
of timestamps the violation appeared between, plus a property delta
showing the change that flipped it.

Two modes:
- `bisect` (default) — O(log N), assumes monotonic transition
- `scan` — O(N), finds ALL violation windows including the earliest;
  correct for non-monotonic histories

**Applied as.** `cmd/bisect/` reads the snapshot archive, runs the
single named control's predicate against each snapshot, and emits
the transition point.

**Problem addressed.** The CISO/IR question: "Our SOC2 audit caught
this misconfiguration today. When did it START?" Bisect is the
forensic primitive — and per the doc's lead: "any invariant —
including ones written today against data captured last year."
Writing a new control today and learning when it would have first
fired historically is the retroactive-audit shape no scanner offers.

**Existing tools.** AWS Config: query history via SQL-like
expressions, but the bisect logic is operator-written each time.
CloudCustodian: doesn't bisect — runs the policy continuously and
records when each finding first appeared. Snyk / Wiz: first-detected
timestamps but no equivalent of "let me write a NEW rule today and
ask when it would have first violated."

---

### 5. Snapshot diff — `stave diff`

**Description.** Compares two observation snapshots and reports every
asset-level configuration change — resources added, removed, or
reconfigured. Same command in catalog-diff mode compares two control
catalog versions.

**Applied as.** `stave diff --snapshot-before <a.json> --snapshot-after
<b.json>` walks both asset trees and emits property deltas.

**Problem addressed.** "We were safe Monday. What specifically changed
to make us unsafe Tuesday?" Drift detection is the inverse of
bisect — bisect goes from violation → transition timestamp; diff goes
from two timestamps → set of changes.

**Existing tools.** AWS Config: `BatchGetResourceConfig` + delta logic
covers this but requires operator-side code. CloudCustodian: doesn't
expose snapshot-diff directly. Wiz: drift detection is a feature but
the diff payload isn't user-facing — it's an alert with no diff body.

**~~⚠️ GAP-A (docs)~~ — closed (Temporal Iteration 1):**
`docs/drift-detection.md` previously described this feature under the
name `stave drift`, but the binary command is `stave diff`. All command
invocations and flag references in `docs/drift-detection.md`,
`docs/bisect-timeline.md`, `README.md.tmpl`, and the
`examples/tlaplus-temporal-safety/README.md` cross-reference now match
the shipped binary (`stave diff --snapshot-before <a> --snapshot-after <b>`).
The doc filename (`drift-detection.md`) is unchanged — "drift detection"
remains the concept; only the command-line invocation was misaligned.

---

### 6. `stave trend` — posture metrics across N assessments

**Description.** Reads a sequence of `stave apply` output files
(assessment JSONs in `out.v0.1` shape) and computes posture metrics:
violation rate, MTTR per severity, severity distribution, attack-stage
trends, velocity, and improvement projection.

**Applied as.** `stave trend --history ./assessments/ --format json`
or `--files run1.json,run2.json,run3.json`.

**Problem addressed.** The board-level / quarterly-review question:
"Are we getting safer?" The CEO doesn't want a count of findings —
they want the slope. MTTR per severity is the operational version
("how fast did we fix it last quarter?").

**Existing tools.** Wiz / Lacework / Orca: posture-trend dashboards
are core CSPM features. The differentiator is that Stave's trend is
**reproducible** (same N assessments → same trend) and **portable**
(an auditor can re-run it from the captured outputs); CSPM trends
are bound to the vendor's database.

---

### 7. `stave budget` — SLA burn-rate in a budget period

**Description.** "Burn rate" is the fraction of the allowed unsafe
window consumed by open violations in a budget period (default 30d).
Lifted from Google SRE's error-budget concept. `stave budget` produces
a gate signal: if you've burned 80% of your monthly budget by day 10,
freeze new deployments until you remediate.

**Applied as.** `stave budget --history ./assessments/ --period 30d
--sla-profile hipaa --fail-on-burn-rate 80 --fail-severity critical`
returns exit 1 if the threshold is exceeded.

**Problem addressed.** Deployment gate. Continuous-delivery teams
want a freeze signal that's quantitative ("we've spent 84% of our
critical budget this month") rather than binary ("any critical
finding blocks").

**Existing tools.** No direct equivalent in CSPM tooling. SRE
error-budget tooling (Sloth, OpenSLO) is bound to availability
metrics, not security posture. This is one of Stave's distinctive
extensions of SRE thinking to security.

---

### 8. `stave watch` — continuous monitor

**Description.** Monitors an observation directory for new snapshots;
runs assessment on each change; detects security regressions,
recoveries, and degradation in real time. Emits alerts to configurable
sinks.

**Applied as.** The extractor drops JSON snapshots into a directory;
`stave watch` detects the inotify change, runs assessment, alerts on
delta.

**Problem addressed.** Bridges Stave from "audit tool" to "continuous
integrity monitor" without requiring cloud credentials.

**Existing tools.** AWS Config has live evaluation. CloudCustodian
runs on schedule. CSPM tools (Wiz, Lacework) do continuous monitoring
inherently because they're SaaS. Stave's distinction: file-based
boundary — the extractor and the monitor are independent processes
that communicate by filesystem.

---

### 9. `stave monitor` — live terminal posture display

**Description.** Single-pane-of-glass terminal view: posture score,
top findings, SLA burn rates, severity distribution. Auto-refreshes;
optional JSON / plain-text output for piping.

**Applied as.** `stave monitor --interval 30s` updates the view every
30 seconds.

**Problem addressed.** The operations dashboard for someone who lives
in a terminal. Not a replacement for Grafana; a fast read for a
platform engineer.

**Existing tools.** No direct equivalent — CSPM tools have web
dashboards but no terminal-native version. `htop` / `glances` /
`ctop` are the visual reference for the UX.

---

### 10. Per-finding `HasTemporalEvidence` flag

**Description.** Boolean on every finding that flips to true when
the snapshot archive carries enough history to establish
`first_unsafe_at`. False when the run was a single-snapshot
evaluation.

**Applied as.** Set by `internal/core/evaluation/`; consumed by
report templates so single-shot runs don't render misleading "unsafe
since the dawn of time" timestamps.

**Problem addressed.** Output correctness — a finding's temporal
evidence is only meaningful if the underlying snapshot archive has
enough history. The flag tells consumers whether to trust the
timestamps.

**Existing tools.** None — this is a Stave-specific output-quality
invariant.

---

### 11. Recurrence tracking — `internal/core/evaluation/recurrence/`

**Description.** Tracks per-finding recurrence across runs: how many
times the same `(control_id, asset_id)` pair has fired, with what
inter-occurrence windows. Used internally by `WindowSummary` and the
SLA computation.

**Applied as.** Internal API; surfaced indirectly through trend output
and burn-rate computation.

**Problem addressed.** "This finding has fired 11 times in the last 30
days" is a stronger triage signal than "this finding is currently
firing." Repeated transient violations are a regression-prone
configuration that needs root-cause investigation.

**Existing tools.** Datadog / PagerDuty: alert-fatigue suppression
based on recurrence patterns. AWS Config: doesn't surface
recurrence — every compliance change is a separate event.

**⚠️ GAP-B (surfacing):** Recurrence is computed but no user-facing
command exposes it directly. A `stave findings --recurrence-only` or
`stave inspect recurrence` subcommand would close the gap.

---

### 12. Time-based predicate fields in 176 controls

**Description.** Across the catalog, 176 controls evaluate
time-derived properties: `is_idle`, `is_dormant`, `appears_unused`,
`last_used_days > N`, `expiry < N`, `last_request_days`,
`last_deployment_days`, `temp_password_valid_days_exceeded`,
`idle_session_ttl_excessive`. The collector pre-computes these
booleans / counts from raw timestamps on the resource side.

**Applied as.** CEL predicates read the pre-computed flags. Examples:
- `CTL.IAM.CRED.UNUSED45.001` — access key not used in 45+ days
- `CTL.LIFECYCLE.STAGING.STALE.001` — non-prod resource idle past threshold
- `CTL.SAGEMAKER.NOTEBOOK.IDLE.001` — notebook idle 30+ days (shipped iter 3)
- `CTL.BEDROCK.AGENT.STALE.001` — Bedrock agent never invoked (shipped iter 6)
- `CTL.ACM.CERT.EXPIRY.001` — certificate near expiry

**Problem addressed.** OWASP NHI1 (Improper Offboarding) at its purest
— identities and resources whose intended lifetime has passed but
whose configuration retains them. Time is the discriminator.

**Existing tools.** AWS Trusted Advisor flags idle resources. AWS
IAM Access Analyzer flags unused permissions. Prowler has individual
checks. Stave's distinctive move is **catalog scale** (176 controls)
+ **consistent surface** (same `unsafe_predicate` shape, same
remediation framing, same compliance metadata).

---

### 12b. Time-Bound Credential Invariant — credential TTL / expiry / rotation

**Description.** A focused subset of item 12: **48 controls**
specifically enforcing that credentials (access keys, tokens,
certificates, KMS material, secrets-manager rotation) carry a
declared TTL and are rotated before that TTL elapses. This is the
single most-mature time-axis feature class in the catalog and
deserves its own row.

Distribution:

| Category | Count | Examples |
|---|---:|---|
| IAM credential TTL / rotation | 10 | `CTL.IAM.CRED.EXPIRY.001` (NHI7 — declares expiry), `CTL.IAM.CRED.TTL.EXCEEDED.001` (NHI7 — TTL elapsed, Iter 2), `CRED.ROTATION.001`, `CRED.UNUSED45.001`, `CRED.UNUSED.001`, `CRED.SETUPKEY.001`, `CRED.SINGLEKEY.001`, `CRED.RECUR.001`, `PASSWORD.ROTATION.001`, `IAM.CERT.EXPIRED.001` |
| Token TTL (Cognito + Bedrock) | 5 | `CTL.COGNITO.CLIENT.REFRESHTTL.001` (>30 days), `ACCESSTTL.001` (>1 hour), `IDTTL.001`, `CTL.BEDROCK.AGENT.SESSION.TTL.001`, `CTL.COGNITO.TEMPPASSWORD.001` |
| Cert / SAML metadata expiry | 11 | `CTL.ACM.CERT.EXPIRY.001`, `CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN`, `ELB.CERT.EXPIRY.WARN`, `APIGATEWAY.DOMAIN.CERT.EXPIRY.WARN`, `APIGATEWAY.NETWORK.CLIENTCERT.EXPIRY`, `OPENSEARCH.CUSTOM.CERT.EXPIRY`, `COGNITO.DOMAIN.CERTEXPIRY`, `COGNITO.SAML.CERTEXPIRED`, `OPENSEARCH.SAML.METADATA.EXPIRED`, `KMS.IMPORTED.EXPIRY`, `KMS.MATERIAL.EXPIRED` |
| AD / Azure / GCP credential lifecycle | 11 | `CTL.AD.ACCOUNT.NOEXPIRY.001`, `AD.KRBTGT.ROTATION.001` (>180d), `AD.PASS.MAXAGE.001`, `AZURE.IDENTITY.SP.EXPIRY`, `AZURE.KEYVAULT.{KEY,SECRET}.EXPIRY` + `KEYVAULT.ROTATION`, `AZURE.STORAGE.KEYROTATION`, `GCP.IAM.APIKEY.ROTATION`, `GCP.IAM.SA.ROTATION`, `GCP.KMS.ROTATION` |
| Secrets Manager rotation | 7 | `CTL.SECRETS.ROTATION.001`, `ROTATION.NEVER`, `ROTATION.STALE`, `ROTATION.INTERVAL.LONG`, `ROTATION.SINGLEUSER.PROD`, `ALARM.ROTATION.FAILURE`, `ALARM.ROTATION.APPROACHING` |
| KMS key rotation | 3 | `CTL.KMS.ROTATION.001`, `KMS.LIFECYCLE.ROTATION.PERIOD.001`, `KMS.ALARM.ROTATION.FAILURE.001` |
| Bedrock long-lived API keys | 1 | `CTL.BEDROCK.ACCESS.LONGTERM.001` |

**Applied as.** Each control reads a collector-precomputed boolean
or count from the observation (e.g.,
`properties.identity.credentials.has_expiry`, `properties.identity.credentials.ttl_exceeded`,
`properties.accounts.krbtgt_password_age_days`). 37 of the 48 carry
an `owasp_nhi: "NHI7"` annotation — they're the backbone of the
OWASP Non-Human Identity Top 10 mapping for Long-Lived Secrets.

**Problem addressed.** The "Time-Bound Credential Invariant" framing
from [`business/collins/first-10.md`](../../business/collins/first-10.md)
(lines 225, 350, 556): *"No credential may exist beyond its
declared TTL."* The strategic argument:

- *Runtime invariant, not a config rule.*
- *Violated silently over time.*
- *Requires continuous reconciliation, not one-time checks.*

This is the canonical Time-as-Adversary failure mode catalogued in
[`business/security-theory/time-adversary.md`](../../business/security-theory/time-adversary.md):
*"Time works against defenders. Credentials age. Humans forget.
Time accumulates risk."*

**Existing tools.** AWS Trusted Advisor flags some idle access keys
+ unused IAM users. AWS IAM Access Analyzer flags unused
permissions. None enforce per-credential declared TTL. Most CSPMs
(Wiz, Lacework, Orca) surface stale credentials but as findings,
not as a runtime invariant. Stave's distinction is **catalog scale**
(48 controls) + **NHI7-mapped consistency** + **strategic framing
as a runtime invariant**.

**✅ GAP-L closed (Temporal Iteration 2).** The layered defense is
now explicit. `CTL.IAM.CRED.EXPIRY.001` verifies an expiry IS
DECLARED (severity high):

```yaml
unsafe_predicate:
  - field: properties.identity.credentials.has_expiry
    op: eq
    value: false
```

`CTL.IAM.CRED.TTL.EXCEEDED.001` (Iter 2, severity critical, NHI7)
verifies the TTL HAS NOT ELAPSED:

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: user
    - field: properties.identity.credentials.has_expiry
      op: eq
      value: true
    - field: properties.identity.credentials.ttl_exceeded
      op: eq
      value: true
```

Same shape as `CTL.AD.KRBTGT.ROTATION.001` which checks
`krbtgt_password_age_days > 180` rather than just "rotation is
enabled." The collector pre-computes `ttl_exceeded` from
`now - declared_expiry_at`; the control reads the boolean. Fixtures
under `examples/iam-cred-ttl-exceeded/` (`ttl-exceeded`,
`ttl-valid`, `no-expiry`) verify the matrix: EXCEEDED fires 1/0/0
and EXPIRY fires 0/0/1 — the two controls are independent and
compose as layered defense.

---

### 13. Temporal ghost detection

**Description.** Two controls (per commit `28b41bb9b`) confirm a
"ghost reference" by observing the same asset across two snapshots:
the referenced resource existed in snapshot A, disappeared by
snapshot B, but the reference persists in snapshot B. Higher
confidence than single-snapshot ghost detection.

**Applied as.** Collector emits the cross-snapshot evidence
(`appeared_in_prior_snapshot: true`, `target_exists_now: false`);
the control reads the booleans.

**Problem addressed.** Ghost references are the **historical** failure
mode — the resource was real, then deleted, then the reference became
a ghost. Single-snapshot detection can be wrong if the asset is just
not yet captured by the collector (race condition). Two-snapshot
confirmation eliminates the race.

**Existing tools.** No commercial equivalent — ghost references in
general are a Stave invention (the broader catalog has 23 ghost
controls). Temporal confirmation is a refinement.

**~~⚠️ GAP-C (docs)~~ — closed (Temporal Iteration 1):**
[`docs/temporal-ghost.md`](temporal-ghost.md) now documents the
two temporal-ghost controls (`CTL.GHOST.TEMPORAL.RESOURCE.001` +
`CTL.GHOST.TEMPORAL.PERMISSION.001`), their relationship to the
single-snapshot ghost family (23 controls), the
`governance.temporal_analysis` synthetic asset the collector emits
for cross-snapshot comparison, and severity inheritance rules.

---

### 14. Exposure window tracking — `internal/core/asset/`

**Description.** Tracks per-asset exposure windows: when the asset
first entered an unsafe state, when it returned to safe. Critical
detail per commit `c5387ffea`: the window closes on the *secure*
observation, not the last unsafe one — so the duration computation
includes the time the asset was passing the predicate again, which
is the auditor-friendly interpretation.

**Applied as.** Internal API consumed by SLA evaluation and
trend reporting.

**Problem addressed.** Subtle correctness bug: if you close the
window on "last seen unsafe," you miss the period of exposure
between the last unsafe observation and the secure one. Closing on
the secure observation matches the natural-language semantics
auditors expect.

**Existing tools.** Most posture-trend implementations get this wrong
in subtle ways. AWS Config's history retention is correct but
querying it requires explicit window logic.

---

### 15. TLA+ temporal safety — `examples/tlaplus-temporal-safety/`

**Description.** External engine that explores state space around the
current snapshot under "any single configuration knob may flip" as
the transition relation. Computes **drift margin** — the minimum
number of toggles separating the current safe state from a violation.

**Applied as.** `bash examples/tlaplus-temporal-safety/run.sh` runs
the TLA+ model checker over the SIR-exported state.

**Problem addressed.** Static analysis answers "is the current
snapshot safe?" Drift margin answers "how close to unsafe are we?" A
drift margin of 1 means a single human error away from breach; a
drift margin of 4 means a much larger blast radius for individual
mistakes.

**Existing tools.** TLA+ itself is used widely for distributed-systems
correctness (S3, DynamoDB, AWS internal services). Applying it to
cloud-config drift is unusual. No commercial CSPM exposes anything
resembling drift margin.

---

### 16. `examples/forecast/` — linear-trend posture projector

**Description.** External Python implementation of `app/forecast/` —
reads N `out.v0.1` assessment files, fits closed-form least-squares on
the per-day score series, projects N days forward, emits per-severity
SLA status (`ON_TRACK` / `AT_RISK` / `BREACHING`). Shipped as part of
the core-bloat migration; the internal `app/forecast/` is deprecation-
ready once `CompoundFinding` consumer untangling lands.

**Applied as.** `./examples/forecast/forecast.py <assessments-dir>
--horizon 30 --sla-profile sla.json`.

**Problem addressed.** "If our posture decline continues at the
current slope, when do we breach SLA?" Quarter-out forecasting for
quarterly OKR reviews.

**Existing tools.** No direct equivalent in CSPM. SRE error-budget
projections are the closest concept; Stave applies the same math to
security posture.

**⚠️ GAP-D (surfacing):** External example only. A `stave forecast`
subcommand wrapping the script (same way `stave trend` wraps trend
computation) would make the feature discoverable. Today an adopter
has to know to look under `examples/`.

---

### 17. Severity-keyed SLA profiles

**Description.** SLA profiles in YAML allow per-severity unsafe-window
deadlines (e.g., critical: 24h, high: 72h, medium: 168h, low: 720h).
The 10 shipped compliance profiles (HIPAA, SOC2, PCI-DSS, …) declare
these in their metadata.

**Applied as.** `stave apply --sla-profile hipaa` loads the per-severity
windows from the profile; `stave budget --sla-profile hipaa` applies
the same to burn-rate computation.

**Problem addressed.** "Critical findings have 24-hour SLA; low
findings have 30-day SLA" — single global `--max-unsafe` collapses
this important differentiation.

**Existing tools.** Most CSPMs implement this — Wiz / Lacework /
Datadog all have severity-keyed SLAs.

**~~⚠️ GAP-E (ergonomics)~~ — closed (Temporal Iteration 1):**
`internal/adapters/sla/provider.go` now loads the embedded `default`
SLA profile when both `--sla-profile` and `--sla-profile-file` are
unset. Severity-keyed SLA evaluation is therefore on by default with
the deadlines declared in
[`internal/adapters/sla/embedded/default.yaml`](../internal/adapters/sla/embedded/default.yaml)
(critical: 72h, high: 336h, medium: 1440h, low: 4320h, escalation
factor: 1.5). The flags retain their existing semantics — file path
beats profile name beats default — but the user-facing surface is
"works out of the box" instead of "you must discover the flag."

---

### 18. Observation freshness / extractor-staleness — ~~GAP-F~~ closed

**Description.** Observations carry `captured_at`, and the
extractor emits a synthetic `aws_observation_meta` asset describing
the freshness state of the collector run itself. If the extractor
stops, the most recent snapshot ages out; without a meta-control
Stave would keep evaluating stale data and reporting "no new
findings" — false negative by silence.

**Shipped as.** `CTL.META.OBSERVATION.STALE.001` (governance / NHI8
/ severity high, attack_stage `detection_evasion`). Fires when the
collector-precomputed boolean `properties.meta.observation.is_stale`
is true:

```yaml
scope_tags: [aws, meta]
unsafe_predicate:
  all:
    - field: properties.meta.kind
      op: eq
      value: observation_meta
    - field: properties.meta.observation.is_stale
      op: eq
      value: true
```

Fixtures under `examples/meta-observation-stale/` (`stale`, `fresh`,
`boundary`) confirm the predicate fires 1/0/0 — the boundary case
(captured exactly at the threshold) is intentionally treated as
fresh.

**Problem addressed.** The "extractor died silently and dashboards
went green" failure mode. The dog that didn't bark, applied to
observability infrastructure.

**Existing tools.** None of the CSPM tools have this because they
own the collector — if their collector breaks, their pipeline screams.
Stave's file-boundary architecture makes this an explicit concern,
so it ships as an explicit canary control.

---

### 19. Intent expiry — **GAP-G**

**Description (proposed).** "Monday: a permission is created for a
specific project. Tuesday: the project ends; the intent for that
permission vanishes. The configuration didn't change but the
permission is now stale." `temporal-dimension.md` flags this as the
"clock that ran out" failure mode.

**Applied as.** Would require a `reviewed_at` / `expires_at` tag
on resources + a control comparing `now - reviewed_at` to a
threshold, OR a `business_intent.expires_at` field in the
observation.

**Problem addressed.** The slowest-moving failure mode — nothing
in the config changed; the *business reality* changed. Stave can
detect it only if the collector materializes intent into observation
data.

**Existing tools.** No tool addresses this directly. Some companies
implement it via custom `Last-Reviewed` tags + ad-hoc audits.

---

### 20. Long-horizon causality — **GAP-H** (scope boundary)

**Description.** "This regression today was caused by IaC commit
6 months ago" — requires attributing snapshot changes back to
specific human actions (CloudTrail events, IaC commits, change
tickets).

**Applied as.** Not Stave's domain — this is the **collector's**
job. Stave's snapshot diff says "property X went from A to B between
these two snapshots"; tying that delta back to a specific commit or
actor lives in CloudTrail / Atlantis logs / GitOps tooling.

**Problem addressed.** Forensic attribution beyond bisect's
"between snapshot A and B" window.

**Existing tools.** Cyera / Wiz / Datadog all do this by ingesting
CloudTrail and correlating. Stave's air-gapped model deliberately
excludes this — it's a known boundary.

---

### 21. Silent-monitoring-collapse over time — **GAP-I**

**Description.** `chains/silent_monitoring_collapse.yaml` and
`chains/cloudwatch_silence_as_safety.yaml` detect monitoring gaps in
the *current* configuration (missing alarms, missing log filters,
missing notification targets). They don't detect "the alarm exists
but hasn't fired in 30 days when it should have" — the absence of
expected alerting events over time.

**Applied as.** Today: single-snapshot compound chains. Proposed:
control that consumes CloudWatch alarm-history / metric data to
flag alarms with zero alerts in their configured period.

**Problem addressed.** "The dog that didn't bark" — silence as
evidence. An alarm that should have fired but didn't is a stronger
signal than a missing alarm.

**Existing tools.** CSPMs generally don't model alarm-history
absence. Datadog Monitors have a "no-data" feature that flags
metrics with no samples — closest commercial peer.

---

### 22. Time travel / "what did our posture look like on date X" — **GAP-J**

**Description.** Today: `stave apply --now <past-date>
--observations <archive-from-that-date>` works for the fixtures from
that date. Proposed: `stave timetravel --date 2026-01-15 --archive
<dir>` automates the "find the snapshot from this date and run the
current control set against it" workflow.

**Applied as.** Composition of bisect + apply with a date input.

**Problem addressed.** "We rolled out a new control today. What
would it have flagged in our environment six months ago?" The
retroactive-audit shape `docs/bisect-timeline.md` motivates but
bisect only handles single-control transition search, not full
historical assessment.

**Existing tools.** AWS Config conformance packs can query
historical state. Wiz's "time machine" is the closest commercial
peer.

---

### 23. Cross-control temporal compound — **GAP-K**

**Description.** Today: compound chains compose findings that are
*currently* firing on the same asset (or scope-linked assets).
Proposed: compound chains that fire when control A fired first,
then control B fired N days later — a temporal-ordering chain.

**Applied as.** Would require the chain engine to consult per-finding
`first_unsafe_at` and enforce an ordering constraint.

**Problem addressed.** Attack-progression detection. "Credential
exposed → role assumed → S3 accessed" has a natural temporal order;
firing all three simultaneously means one of them is stale; firing
them in order means the attack is in progress.

**Existing tools.** SIEM tools (Splunk, Datadog Security) do
temporal correlation on log events. None do it on config-posture
findings.

---

## Summary

Stave's time model is **deep on the per-finding axis** (timestamps,
duration, SLA, burn rate, exposure windows), **shipped on the
trajectory axis** (trend, forecast, budget), and **shipped on the
forensic axis** (bisect, diff, recurrence, temporal-ghost). The
gaps cluster around:

- **Documentation hygiene** (A, C) — small, sub-hour edits
- **Surfacing of internal capabilities** (B, D) — recurrence and forecast
  are computed but not first-class commands
- **Ergonomic polish** (E) — severity-keyed SLA as the default
- **Air-gap-architecturally-out-of-scope** (H) — causality attribution
  lives in the collector / IaC log world, not Stave
- **Genuine feature extensions** (F, G, I, J, K) — observation
  freshness, intent expiry, silent-alarm-history, time-travel reports,
  cross-control temporal compound chains. These are the future-work
  list; the first three are single-iteration additions, the last two
  are deeper architectural questions.

The temporal-dimension argument (`temporal-dimension.md`,
`d27b7f748`) frames time as the structural wall between Stave and
AI scanners. The audit confirms: Stave shipped most of the
foundational time machinery (items 1–17) but has named gaps in the
"intent over time" axis (G), the "monitoring silence over time"
axis (I), and the retroactive-replay UX (J). Closing G, I, J would
complete the temporal story this document opens.
