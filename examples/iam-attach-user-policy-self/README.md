# Example — IAM Self-Attach (Rhino Technique #1)

Demonstrates the `iam-attach-user-policy-self` pattern using
both **CEL** (`pkg/stave`) and **Z3** (the
`aclements/go-z3` binding). Pattern P6 in
[`examples-plan.md`](../../../examples-plan.md), grounded in
**Rhino Security Labs' 2018 IAM privilege-escalation
catalogue** (Spencer Gietzen) — technique #1, "IAM — Attach
to user".

The bug: an IAM user has `iam:AttachUserPolicy` whose
Resource includes the user's own ARN. One API call —

```bash
aws iam attach-user-policy \
  --user-name self \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

— makes the user admin. No other permission, no exploit, no
social step. This is the cleanest one-step privesc in
Rhino's catalogue and remains the simplest IAM bug to ship
to production by mistake.

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

## Two binaries, two questions

```
examples/iam-attach-user-policy-self/
├── README.md
├── main.go              # CEL: does the unsafe predicate hold?
├── controls/
│   └── CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # iam:AttachUserPolicy on self
│   └── after/observations/{T1,T2}.json    # AttachUserPolicy removed
├── z3prove/
│   ├── go.mod           # separate module — CGO/libz3 stays out of stave/
│   └── main.go          # Z3: which managed policy makes the user admin?
└── expected/
    ├── before-output.txt
    ├── after-output.txt
    ├── z3-before-output.txt
    └── z3-after-output.txt
```

`z3prove/` is a separate Go module (mirrors iter-4, iter-5,
iter-7a) so its libz3 link does not infect Stave's
vendored tree.

## CEL side

From `stave/`:

```bash
go run ./examples/iam-attach-user-policy-self           # both phases
go run ./examples/iam-attach-user-policy-self before    # vulnerable only
go run ./examples/iam-attach-user-policy-self after     # remediated only
```

Captured output:

```
=== before (self-attach allowed) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001 fired on 1 asset(s):
    - arn:aws:iam::111122223333:user/eve   severity=critical   exposure_score=100.00
  assertion: fires=true (expected) ✓

=== after  (self-attach removed) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001: no findings
  assertion: fires=false (expected) ✓
```

Severity is `critical`, exposure score 100 — this is the
highest the engine can produce on a single control, because
the unsafe state is *one API call away from full account
admin*. There is no graduated risk; either the user can
self-attach an admin policy or it cannot.

## Z3 side

Prerequisites (Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/iam-attach-user-policy-self/z3prove
go mod tidy
CGO_ENABLED=1 go run . before
CGO_ENABLED=1 go run . after
```

Captured output for `before`:

```
=== before (self-attach allowed) ===
  user: arn:aws:iam::111122223333:user/eve
  policy statements: 2
    [0] Effect=Allow Action=[iam:GetUser iam:ListAttachedUserPolicies] Resource=arn:aws:iam::111122223333:user/eve
    [1] Effect=Allow Action=iam:AttachUserPolicy Resource=arn:aws:iam::111122223333:user/eve
  iam:AttachUserPolicy on self admitted: true
  dangerous witnesses: [arn:aws:iam::aws:policy/AdministratorAccess arn:aws:iam::aws:policy/IAMFullAccess arn:aws:iam::aws:policy/PowerUserAccess]
  verdict: SAT — witness: attach arn:aws:iam::aws:policy/AdministratorAccess → user becomes admin
```

Z3 returns SAT with the specific managed policy whose
attachment makes the user admin —
`arn:aws:iam::aws:policy/AdministratorAccess`. The article
quotes this verbatim as the demonstrated breach.

For `after`:

```
=== after  (self-attach removed) ===
  user: arn:aws:iam::111122223333:user/eve
  policy statements: 1
    [0] Effect=Allow Action=[iam:GetUser iam:ListAttachedUserPolicies iam:ChangePassword] Resource=arn:aws:iam::111122223333:user/eve
  iam:AttachUserPolicy on self admitted: false
  dangerous witnesses: [arn:aws:iam::aws:policy/AdministratorAccess arn:aws:iam::aws:policy/IAMFullAccess arn:aws:iam::aws:policy/PowerUserAccess]
  verdict: UNSAT — no admin-granting policy is attachable
```

UNSAT — `iam:AttachUserPolicy` is gone, so no managed
policy can be attached, so no admin-granting policy is
reachable.

## What the Z3 program does

The fixture observation carries the user's attached policy
statements under
`properties.identity.policies.attached_policies`. The Z3
program:

1. Reads each statement's Action and Resource.
2. Decides whether `iam:AttachUserPolicy` with the user's
   own ARN is admitted (`*` action, `iam:*`, or exact
   action match; `*`, `arn/*`, or exact resource match).
3. Encodes a finite witness set of AWS-managed policies:
   ```
   0 = ReadOnlyAccess         intended (no privesc)
   1 = AdministratorAccess    DANGEROUS
   2 = IAMFullAccess          DANGEROUS
   3 = PowerUserAccess        DANGEROUS
   ```
4. Asks Z3 to find a policy that is admittable AND
   dangerous AND not intended.

The clever part: when self-attach is admitted, *every*
managed policy is admittable (the user can attach
anything). Z3's contribution is finding the specific
dangerous one that was hiding in the catalogue.

## Modelling note: scope of the witness set

This program models a small finite catalogue of
admin-granting AWS managed policies. A production analyser
would parse the actual managed-policy documents and check
which grant admin (any policy with `Action: *` /
`Resource: *`, or any policy that grants
`iam:CreatePolicyVersion` / `iam:AttachRolePolicy`, etc.).

The catalogue here is the demonstration surface. The
*encoding pattern* — admit set parameterised on a Go-side
matcher, dangerous set hard-coded, intended set named —
generalises to any IAM privesc technique without changing
the Z3 mechanics.

## Reusing the iter-7a matcher

The `actionMatches` and `resourceMatches` functions in this
program are byte-identical to the ones in
`iam-overpermission-wildcard/z3prove/main.go`. Both
implement the same minimal IAM matcher; future IAM
examples (`iam-non-effective-privilege`,
`iam-passrole-createfunction`) can copy them unchanged.

A future refactor could lift this matcher into a shared
helper module, but at six controls per matcher and
two IAM examples shipped, copy-paste is cheaper than
introducing a new module dependency.

## Where this fits

This is **Iteration 7, Phase B** of the examples roadmap.
Phase C is the article in `channels/devto/`, which uses the
SAT model output as the demonstrated breach path: "the
specific managed policy whose attachment makes Eve admin
is `AdministratorAccess`."
