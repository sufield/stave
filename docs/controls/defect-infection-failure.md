# Authoring Defect / Infection / Failure Metadata

Controls carry three optional prose fields — `defect`,
`infection`, `failure` — that expand finding output
from *"what fired"* to *"what fired and why it
matters."* The vocabulary comes from Andreas Zeller's
*Why Programs Fail*, which describes how defects in
code propagate through runtime state to produce
observable failures. The same chain applies to cloud
misconfigurations: a **defect** in configuration
causes **infected** system state, which results in a
security **failure**.

Stave uses this vocabulary in technical output because
the audience (engineers triaging findings) already
knows it from debugging. A separate compliance export
will translate to CISO/auditor vocabulary in a future
iteration.

## YAML placement

Add as top-level keys alongside `description` and
`remediation`:

```yaml
dsl_version: ctrl.v1
id: CTL.EXAMPLE.001
name: Example Control
description: >
  Short technical description of what this control
  detects.
defect: >
  Specific description of the misconfiguration.
infection: >
  How the defect propagates to enable adverse
  behavior.
failure: >
  Worst-case outcome if exploited.
# ... rest of the control ...
```

All three are optional. Controls without these fields
remain valid; finding rendering skips the empty
sections.

## Writing the Defect

Be specific about what is misconfigured, not about the
class of misconfiguration.

- Defect: *"The bucket's ACL grants AllUsers read
  access."* ✓
- Not defect: *"Public S3 exposure."* ✗ — that's the
  class name, not the specific defect.

Adopters match the Defect text against their own
configuration to recognize the finding. Abstract
class labels don't match; concrete defect
descriptions do.

Length: 1-2 sentences. Name the specific field /
policy / ACL that's wrong.

## Writing the Infection

Describe how the defect propagates to enable
adverse behavior. Plain mechanism language focused
on how a defect turns into something exploitable.

- Infection: *"Anyone on the internet can fetch
  objects from this bucket over anonymous HTTP. Search
  engines continuously enumerate public bucket names,
  meaning exposure is active from the moment the ACL
  is set."* ✓
- Not infection: *"High risk."* ✗ — risk labels don't
  describe propagation mechanics.

Adopters use the Infection section to decide whether
the defect matters in their context. An adopter might
accept a defect they think is contained; the
Infection text tells them whether the containment
assumption is sound.

Length: 2-3 sentences. Describe the mechanism
concretely: who triggers the adverse behavior, how,
and under what conditions.

## Writing the Failure

Describe the worst-case outcome if the infection is
exploited. Adopter-meaningful terms — data exposure,
credential-boundary collapse, cluster compromise,
regulatory-deadline breach. Not abstract CVSS
categories.

- Failure: *"Credential-boundary collapse. The
  account's intended privilege separation no longer
  holds for any attacker who reaches this
  principal."* ✓
- Not failure: *"CIA: High, High, High."* ✗ — CVSS
  vectors aren't worst-case outcomes; they're input
  factors.

Length: 1-2 sentences. Name the worst-case outcome in
language the adopter will use when escalating or
filing a ticket.

## Examples

Three shipped controls use the failure-theory chain:

### `CTL.S3.PUBLIC.001`

```yaml
defect: >
  The bucket's access configuration grants read
  permission to the public — either via a bucket
  policy statement with Principal "*" or via an ACL
  grant to the AllUsers pseudo-group. The bucket is
  reachable without authentication from the public
  internet.
infection: >
  Anyone on the internet can fetch objects from this
  bucket over anonymous HTTP/HTTPS. Search engines and
  automated scanners continuously enumerate publicly-
  indexed bucket names, meaning exposure is active
  from the moment the policy or ACL is in place —
  not hypothetical. Once the bucket name is known,
  every object whose key the caller can guess or
  enumerate is fetchable.
failure: >
  Unbounded data exposure. Every file stored in this
  bucket is readable by arbitrary internet callers,
  including potentially sensitive operational data,
  customer information, backup artifacts, or internal
  documentation that wasn't intended to reach the
  public surface.
```

### `CTL.IAM.NEP.ESCALATION.001`

```yaml
defect: >
  The principal's resolved net effective permissions
  include at least one action that enables privilege
  escalation — for example iam:AttachRolePolicy,
  iam:CreateRole, iam:PassRole on an unscoped
  resource, or a transitive sts:AssumeRole path to
  a higher-privileged role. The escalation is
  present in the policy graph even if the individual
  statements don't look dangerous in isolation.
infection: >
  Any compromise of this principal becomes a
  compromise of every privilege the escalation path
  can reach. An attacker with code execution in a
  service running under this identity (a Lambda, an
  EC2 instance, a CI runner, a human-assumed role)
  exercises the escalation primitive and mints
  themselves broader credentials in a single IAM
  call. For direct primitives, one API call crosses
  the privilege boundary. For transitive chains, a
  short sequence of assume-role calls does the same.
failure: >
  Credential-boundary collapse. The account's
  intended privilege separation (dev vs. prod,
  service vs. admin) no longer holds for any
  attacker who reaches this principal. Post-incident
  forensics typically show a single initial
  compromise expanding to admin-equivalent authority
  within minutes of discovery.
```

### `CTL.ID.KUBE.001`

```yaml
defect: >
  A ClusterRoleBinding references the built-in
  cluster-admin ClusterRole, which grants every verb
  on every resource across every namespace. The
  binding's subject (user, group, or service
  account) holds unconstrained authority over the
  cluster.
infection: >
  Any actor using the bound identity — a compromised
  service account token, a stolen user credential, a
  misconfigured continuous-delivery runner —
  exercises cluster-admin authority without further
  authorization checks. A single `kubectl`
  invocation or API call can modify every workload,
  read every secret, or schedule workloads that
  tunnel through the cluster's networking to reach
  adjacent infrastructure.
failure: >
  Cluster compromise. The entire Kubernetes workload
  — every namespace, every pod, every stored
  secret, every cluster-scoped configuration — is
  accessible to whoever reaches the bound identity.
  Containment usually requires full cluster
  recreation because the cluster-admin authority
  could have rewritten its own audit trail.
```

## Quality bar

An adopter reading the Defect / Infection / Failure
sections should be able to triage the finding without
consulting external documentation. If the content
feels like filler or restates the finding category,
rework until it conveys specific, actionable reasoning.

Two heuristics during authoring:

- **The "grep test"**: if an adopter greps their config
  for the Defect text, would they find the broken
  thing? If yes, the Defect is specific enough.
- **The "priority test"**: if an adopter reads the
  Infection and Failure sections in sequence, can
  they decide whether to page someone now or file a
  ticket for the next sprint? If yes, the prose
  conveys enough context.

If authoring a specific control surfaces ambiguity —
"what is the failure scope?" when the answer depends
on context the catalog doesn't know — write what's
generally true and document the caveat. Don't
speculate beyond evidence. Intent-tag-aware controls
(see `CTL.S3.PUBLIC.LIST.002`'s two-path remediation)
are a precedent for catalog-authored-with-caveat
prose.

## Rendering

Two surfaces render the triage chain:

**CLI text writer** (`stave apply --format text`)
emits the sections on the finding-detail block
between the existing `Reasoning` and `Remediation`
sections. Rendering is **gated on prose presence**:
controls without authored Defect/Infection/Failure
render byte-identically to before (no new sections),
while controls with prose emit `Defect`, `Infection`,
`Failure`, and `Observed`. This preserves golden-
file stability during the authoring transition —
only fixtures whose controls have been authored show
output changes.

**Library consumers** read the sections off the
`pkg/stave.Finding` struct (`Defect`, `Infection`,
`Failure`, `ReasoningTrace`) and render however they
like. See `stave-hackerone-tests/cmd/shopify-1021906/main.go`
and `stave-hackerone-tests/cmd/k8s-rbac-overprivilege/main.go`
for a reference `printTriageChain` helper that emits:

```
DEFECT:
  ...
INFECTION:
  ...
FAILURE:
  ...
OBSERVED:
  <field> = <value>
```

The `OBSERVED` section is derived automatically from
the finding's `ReasoningTrace` — no authoring
required. Library consumers choosing to always render
`OBSERVED` (regardless of prose presence) diverge
slightly from the CLI's gated behavior; both policies
are valid and the fields on the struct are populated
identically in either case.

**JSON output** (`stave apply --format json` and the
library's `Assessment`) carries all three prose fields
with `omitempty` tags: empty fields are absent from
the JSON document, populated fields are present
verbatim.

## Schema requirements

`schemas/control/v1/control.schema.json` permits
`defect`, `infection`, `failure` as optional top-level
string properties. The embedded schema copy at
`internal/contracts/schema/embedded/control/v1/control.schema.json`
must stay in sync (run `make sync-schemas` or copy
manually after schema changes).

## Triage tree separation

Triage prose lives in a separate directory tree from
security definitions:

```
controls/
├── s3/                  Security definitions (predicates,
├── iam/                 classification, severity, scope_tags)
├── ec2/
└── _triage/             Troubleshooting context
    ├── families/        Family-level templates (47 files)
    │   ├── ctl_s3.yaml  infection + failure for CTL.S3.*
    │   └── ...
    └── overrides/       Per-control overrides (121 files)
        ├── CTL.S3.PUBLIC.001.yaml
        └── ...
```

The `_triage/` directory is `_`-prefixed so the
control scanner skips it during YAML discovery. The
engine loads both trees and joins them at runtime.

**Inheritance (per-field):**
1. Per-control override field → use override
2. Family template field → use family template
3. Neither → omit section (OBSERVED still renders)

**Authoring triage:**
- New controls inherit infection/failure from their
  family template automatically. Authors only write
  per-control overrides when the control's context
  differs materially from the family norm.
- Family templates live in
  `controls/_triage/families/<family>.yaml`.
- Per-control overrides live in
  `controls/_triage/overrides/<control-id>.yaml`.
- Defect is always per-control (not family-level).
  Controls without a per-control defect show the
  OBSERVED section as defect evidence.

**Coverage:** 121 controls have full per-control
triage (defect + infection + failure). All 675
controls have at least family-level infection and
failure.
