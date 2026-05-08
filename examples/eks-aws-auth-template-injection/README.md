# Example — EKS aws-auth Template Injection

Demonstrates the `eks-aws-auth-template-injection`
pattern using Stave's library API. Companion to iter-9
(`eks-rbac-webhook-config-access`); this iteration
revives the originally-planned target after the
underlying engine issue turned out to be a fixture
vendor-tag bug.

The bug: a Kubernetes cluster's AWS IAM Authenticator
(`aws-iam-authenticator`) uses
`{{AccessKeyID}}` substitution in identity-mapping
templates. The AccessKeyID is extracted from the
client-supplied presigned STS GetCallerIdentity URL's
query parameters — a value the client controls. With
case-variant duplicate parameters
(`X-Amz-Credential` vs `x-amz-credential`), AWS APIs
normalise to one case while the authenticator's URL
parser uses the other; an attacker can inject a
different AccessKeyID, hijacking another user's
identity in the cluster's RBAC mapping.

This is the disclosed bug behind HackerOne report
[Kubernetes #1580493](https://hackerone.com/reports/1580493),
2022. The fix is to substitute from server-derived
fields (`SessionName`, role ARN) — values the client
cannot influence.

## Prerequisites

This example's `z3prove/` binary links against libz3 via CGO.
Install the development headers before running:

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y libz3-dev pkg-config` |
| macOS (Homebrew) | `brew install z3 pkg-config` |

Then build with `CGO_ENABLED=1 go run .` from inside `z3prove/`.
The Stave binary itself has no libz3 dependency; only the
per-example Z3 prover does. See [`../PREREQUISITES.md`](../PREREQUISITES.md)
for other platforms (Fedora, Arch, nix, Debian) and for the
prerequisites of the SMT CLI / Soufflé / Prolog / Python-venv
examples.

## Plan-correction trail (recorded for traceability)

- The original `examples-plan.md` listed iter-9 as
  `eks-aws-auth-ghost-role`. The actual disclosed bug
  is template injection, not ghost role.
- During iter-9 Phase A, the existing
  `e2e-h1-kubernetes-1580493` fixture appeared to
  silently drop the `k8s_cluster` asset (total_assets=0),
  which was filed as a Stave engine gap. iter-9
  pivoted to a working K8s control
  (`CTL.K8S.RBAC.WEBHOOK.001`) so the iteration could
  ship.
- A subsequent investigation showed the "engine gap"
  was actually a **fixture vendor mismatch**: the
  fixture used `vendor: "aws"` but the K8s control's
  `scope_tags: [kubernetes, auth]` excluded
  AWS-vendored assets via the
  `kernel.AppliesToVendor` heuristic. With
  `vendor: "kubernetes"`, the asset loads and the
  control's predicate evaluates correctly.
- The fixture was corrected
  (`testdata/e2e/e2e-h1-kubernetes-1580493/`) and its
  goldens regenerated in the same change that shipped
  this example.

## What it does

Loads two fixture snapshot directories — fixtures/before
(`uses_access_key_id: true`) and fixtures/after
(`uses_access_key_id: false`, `SessionName` and role
ARN templates) — and asserts that
`CTL.K8S.AUTH.ACCESSKEYMAP.001` fires on the first and
is silent on the second.

## Run

From `stave/`:

```bash
go run ./examples/eks-aws-auth-template-injection           # both phases
go run ./examples/eks-aws-auth-template-injection before    # template-injection only
go run ./examples/eks-aws-auth-template-injection after     # remediated only
```

## Expected output

```
=== before ({{AccessKeyID}} template) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.K8S.AUTH.ACCESSKEYMAP.001 fired on 1 asset(s):
    - acme-eks-cluster   severity=high   exposure_score=76.64
  assertion: fires=true (expected) ✓

=== after  ({{SessionName}} + role ARN) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.K8S.AUTH.ACCESSKEYMAP.001: no findings
  assertion: fires=false (expected) ✓
```

## The Predicate

```yaml
unsafe_predicate:
  all:
    - field: properties.auth.kind
      op: eq
      value: cluster
    - field: properties.auth.webhook.identity_mapping.uses_access_key_id
      op: eq
      value: true
```

`uses_access_key_id` is the engine's verdict — true
when the identity-mapping templates substitute
`{{AccessKeyID}}`. The fixture also carries the
underlying `templates` array as evidence.

## Why Z3 doesn't help

Same answer as the other presence-check iterations:
the collector observes a boolean derived from the
template strings (`{{AccessKeyID}}` is/isn't in any
template), and CEL's predicate is a two-leaf
conjunction. There's no logical search space.

A different question — "given the URL parser's
normalisation rules, is there a query-string
encoding that produces a different AccessKeyID than
STS would resolve?" — *would* be reachability-shaped,
but that's URL-parser semantics, not configuration
semantics.

## Vendor-tag note

The asset's `vendor` field is `"kubernetes"`, not
`"aws"`. EKS clusters run on AWS infrastructure but
are Kubernetes-domain assets; the control's
`scope_tags: [kubernetes, auth]` trips the
vendor-applicability heuristic
(`kernel.AppliesToVendor`) which excludes AWS-vendored
assets. This is intentional engine behaviour — the
heuristic prevents AWS-specific controls from running
on Kubernetes-vendored assets and vice versa. For
EKS-shaped assets that genuinely live in both
domains, choose the domain whose controls you want to
fire and tag accordingly.

The
[`testdata/e2e/e2e-h1-kubernetes-1580493/`](../../testdata/e2e/e2e-h1-kubernetes-1580493/)
fixture used to mis-tag this as `vendor: "aws"` and
silently dropped the asset; that fixture has been
corrected in the same change that shipped this
example.

## Layout

```
examples/eks-aws-auth-template-injection/
├── README.md
├── main.go
├── controls/
│   └── CTL.K8S.AUTH.ACCESSKEYMAP.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # uses_access_key_id=true × 2 weeks
│   └── after/observations/{T1,T2}.json    # uses_access_key_id=false × 2 weeks
└── expected/
    ├── before-output.txt
    └── after-output.txt
```

## Where this fits

This is **Iteration 9b** of the examples roadmap —
the originally-planned EKS target, revived after the
fixture-vendor correction. iter-9
(`eks-rbac-webhook-config-access`) and iter-9b
(this example) ship together as the EKS pair: one is
RBAC-shaped, one is auth-template-shaped, both fire
on the same `kubernetes`-vendored asset class.
