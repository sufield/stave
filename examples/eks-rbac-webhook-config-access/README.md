# Example — EKS RBAC Webhook Config Access

Demonstrates the `eks-rbac-webhook-config-access` pattern
using Stave's library API. Pattern P8 in
[`examples-plan.md`](../../../examples-plan.md), but with a
narrative pivot recorded below.

The bug: a Kubernetes ClusterRole grants
`create / update / patch / delete` on
`mutatingwebhookconfigurations` (or
`validatingwebhookconfigurations`). Any subject bound to
that ClusterRole — typically a ServiceAccount used by an
operator running in the cluster — can register an
admission webhook that intercepts every API call to the
cluster: pod creation, secret reads, deployment updates,
ConfigMap writes. The webhook becomes a persistence-as-a-
service primitive that survives the rest of the cluster's
controls.

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

## Plan-correction note

The original `examples-plan.md` listed iter-9 as
`eks-aws-auth-ghost-role` and pointed at HackerOne report
1580493 (Kubernetes). Two corrections surfaced during
Phase A:

1. The actual disclosed bug in 1580493 is **AccessKeyID
   template injection** in the AWS IAM Authenticator
   identity-mapping templates — not ghost-role
   recreation. The control
   `CTL.K8S.AUTH.ACCESSKEYMAP.001` exists for that
   pattern.
2. The engine silently drops `k8s_cluster` (and
   `aws_eks_cluster`) assets even with
   `--allow-unknown-input`, so the AccessKeyID-injection
   control's predicate cannot fire on real input. This
   is a Stave engine gap — separate from any iteration —
   that will need a small extractor or asset-type
   registration to close.

This example pivots to a working K8s control —
`CTL.K8S.RBAC.WEBHOOK.001`, asset type `k8s_cluster_role`
— that captures a related but distinct EKS-relevant
attack: **persistence via writable admission webhooks**.
The narrative arc still teaches the same lesson at the
RBAC layer.

## What it does

Loads two fixture snapshot directories and asserts that
`CTL.K8S.RBAC.WEBHOOK.001` fires on the first (the role
has webhook-config write access) and is silent on the
second (the role's webhook verbs are scoped to read-only).

## Run

From `stave/`:

```bash
go run ./examples/eks-rbac-webhook-config-access           # both phases
go run ./examples/eks-rbac-webhook-config-access before    # write granted
go run ./examples/eks-rbac-webhook-config-access after     # read-only
```

## Expected output

```
=== before (webhook write granted) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.K8S.RBAC.WEBHOOK.001 fired on 1 asset(s):
    - acme-platform-controller   severity=high   exposure_score=76.64
  assertion: fires=true (expected) ✓

=== after  (read-only) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.K8S.RBAC.WEBHOOK.001: no findings
  assertion: fires=false (expected) ✓
```

## The Predicate

```yaml
unsafe_predicate:
  all:
    - field: properties.k8s.kind
      op: eq
      value: cluster_role
    - field: properties.k8s.rbac.has_webhook_config_access
      op: eq
      value: true
```

`properties.k8s.rbac.has_webhook_config_access` is the
engine's pre-computed verdict — true if any rule in the
ClusterRole grants a write verb
(`create`, `update`, `patch`, `delete`) on
`mutatingwebhookconfigurations` or
`validatingwebhookconfigurations`. The fixture also
carries the underlying `rules` array under the same
`rbac` block as evidence; the article quotes both the
boolean and the rules.

## Why Z3 doesn't help

Same answer as the other presence-check iterations: the
collector observes the role's verb set and computes a
boolean. There's no logical search space. CEL evaluates
the boolean.

A different question — "given this role's full RBAC
binding graph, which subjects can mint a mutating
webhook?" — would be reachability-shaped (chain
write-permission through nested role bindings) and would
benefit from Z3. That's not in scope here.

## Layout

```
examples/eks-rbac-webhook-config-access/
├── README.md
├── main.go
├── controls/
│   └── CTL.K8S.RBAC.WEBHOOK.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # webhook verbs include write
│   └── after/observations/{T1,T2}.json    # webhook verbs read-only
└── expected/
    ├── before-output.txt
    └── after-output.txt
```

## Where this fits

This is **Iteration 9, Phase B** of the examples roadmap.
No new `pkg/stave` API was needed. Phase C is the article
in `channels/devto/`, framed as the "admission webhook as
persistence primitive" angle.
