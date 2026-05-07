# IAM Auto Scaling Privilege Escalation: Deny Policy Bypass Proof

## What this demonstrates

A 2022 Medium writeup by Edoardo Rosa documents a privilege
escalation in which the AWS-managed `DataScientist` policy
plus `AmazonElasticMapReduceFullAccess` plus an explicit
`DemoDenyPrivEscs` deny policy still admits a path to admin
via EC2 Auto Scaling. The Deny lists six classic privesc
actions (`cloudformation:CreateStack`,
`cloudformation:UpdateStack`, `ec2:RunInstances`,
`lambda:Create*`, `lambda:Update*`, `lambda:InvokeFunction`).
The Allow grants `autoscaling:*` from `DataScientist` and
`iam:PassRole` from `EMRFullAccess`. The combination
`autoscaling:CreateLaunchConfiguration` +
`autoscaling:CreateAutoScalingGroup` reaches the same
outcome as `ec2:RunInstances` — launching an EC2 with a
specified instance profile — through a path the Deny
doesn't cover.

The researcher found one bypass through expert manual
inspection. Z3 finds five.

## Three Z3 verdicts on the writeup config

| Finding | Verdict | Witness |
|---|---|---|
| 1 — deny coverage gap | **SAT** | `autoscaling` vector (1 of 9 vectors available; 5 of 9 not denied) |
| 2 — PassRole reaches an admin role | **SAT** | `demo-EC2Admin` (trusts `ec2.amazonaws.com`, `AdministratorAccess`) |
| 3 — compound chain | **SAT** | autoscaling + demo-EC2Admin + EC2 trust → admin in 3 API calls |

## Three Z3 verdicts on the remediated config

| Finding | Verdict | Notes |
|---|---|---|
| 1 — deny coverage gap | **UNSAT** | All 9 vectors blocked by the expanded deny |
| 2 — PassRole reaches an admin role | **SAT** ⚠ | **RESIDUAL** — PassRole is still scoped only by service, not by role ARN |
| 3 — compound chain | **UNSAT** | No launch vector available; PassRole's reachable role has nowhere to land |

The residual SAT on Finding 2 is the article's central
teaching beat. The remediated config closes today's known
nine vectors; it does not close the underlying
architectural issue. AWS adds new compute services
regularly. Each new service that supports an instance
profile (or task role, or execution role) becomes an
exploit path until the deny list is expanded again. The
correct architectural fix is scoping `iam:PassRole` to
specific role ARNs — not maintaining an ever-growing deny
list.

## CEL side — `main.go`

Scoped to `CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001`,
the catalogue's existing per-technique control for this
exact bypass. The control reads
`properties.identity.escalation.passrole_autoscaling.present`
— a boolean the engine's chain walker pre-computes. On
the writeup config that boolean is `true`; on the
remediated config the deny closes the autoscaling path
and the boolean flips to `false`.

Run from `stave/`:

```bash
go run ./examples/iam-autoscaling-privesc-bypass
```

Captured output (`expected/cel-output.txt`):

```
=== writeup-config (DataScientist + EMR + DenyPrivEscs) ===
  status: NON_COMPLIANT   total_assets=2   violations=1
  CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001 fired on 1 asset(s):
    - arn:aws:iam::111122223333:user/demo-DataScientist   severity=high

=== remediated-config (deny expanded to all known compute-launch vectors) ===
  status: COMPLIANT   total_assets=2   violations=0
  CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001: no findings
```

The CEL control covers the autoscaling technique
specifically. It does not enumerate the broader landscape
(ECS, CodeBuild, Glue, SageMaker) and does not surface
the PassRole-scoping residual. That's the Z3 prover's
job.

## Z3 prover — `z3prove/`

Three queries × two configs = six verdicts plus a
per-vector deny coverage table. Prerequisites (Ubuntu):
`sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/iam-autoscaling-privesc-bypass/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

Captured output (`expected/z3-output.txt`). The deny
coverage table on the writeup config:

```
--- Deny coverage analysis ---
  ec2             BLOCKED    : Direct EC2 launch with instance profile
  lambda          BLOCKED    : Create Lambda with execution role
  lambda          BLOCKED    : Update existing Lambda to use different execution role
  cloudformation  BLOCKED    : Create CloudFormation stack with execution role
  autoscaling     NOT BLOCKED : Auto Scaling launch config + group with instance profile
  ecs             NOT BLOCKED : Run ECS task with task role
  codebuild       NOT BLOCKED : Create and start CodeBuild project with service role
  glue            NOT BLOCKED : Create Glue job with execution role
  sagemaker       NOT BLOCKED : Create SageMaker notebook with execution role
```

Five vectors not covered by the writeup's deny. After
remediation, all nine read `BLOCKED`.

## What each query proves

### Finding 1: deny coverage gap

For each of 9 known compute-launch vectors, the prover
checks whether *every required action* is in some Allow
statement and *not* in any Deny statement. Any vector
whose required actions all pass that test is reachable.
Z3's SAT search returns the first reachable vector as
the witness.

The compute-launch registry
(`z3prove/registry.go`) lists the 9 vectors:

- `ec2:RunInstances`
- `lambda:CreateFunction`, `lambda:UpdateFunctionConfiguration`
- `cloudformation:CreateStack`
- `autoscaling:CreateLaunchConfiguration` + `autoscaling:CreateAutoScalingGroup`
- `ecs:RunTask`
- `codebuild:CreateProject` + `codebuild:StartBuild`
- `glue:CreateJob`
- `sagemaker:CreateNotebookInstance`

Each vector is a known way to launch compute with a
specified IAM role. Adding a new vector to the registry
is a single struct entry; the rest of the prover handles
it automatically.

### Finding 2: PassRole reaches an admin-equivalent role

The fixture's `demo-EC2Admin` role trusts
`ec2.amazonaws.com` and has `AdministratorAccess`. The
principal's `AmazonElasticMapReduceFullAccess` policy
grants `iam:PassRole` with a condition restricting to
`iam:PassedToService` ∈ {EMR, EC2}. The condition is
scoped *by service*, not by *role ARN*. Any role
trusting one of the listed services is passable.

Z3's witness search finds `demo-EC2Admin`.

This finding remains SAT after remediation. Closing the
launch vectors does not change which roles are
PassRole-reachable; it only changes whether the
principal can use them. The architecture remains fragile
in a way Finding 3 makes precise.

### Finding 3: complete privesc chain

The conjunction: a launch vector is reachable AND a
PassRole-reachable role is admin-equivalent AND the
role's trust relationship matches the vector's
`PassedToService`. On the writeup config: SAT, with the
autoscaling vector + `demo-EC2Admin` + EC2 trust.

On the remediated config: UNSAT. Finding 1 has closed
all launch vectors; the role reachable in Finding 2 has
no compute service to assume into.

## The matcher additions for this iteration

This iteration extends the IAM matcher template
established in iter-7a / iter-7 with two new pieces:

1. **Allow + Deny effective-permission resolution**.
   Previous IAM iterations checked whether one Allow
   admitted a specific action. This iteration walks
   *both* statement sets — Allow first, then Deny —
   and reports the action as effectively allowed only
   when it appears in some Allow and no Deny. Live in
   `actionEffectivelyAllowed` /
   `actionsAllDenied`.

2. **`iam:PassedToService` condition handling**. The
   `extractPassedToServices` helper reads the
   `Condition.StringEquals.iam:PassedToService` block
   from a PassRole statement and returns the service
   list. `passRoleAdmitsTrust` checks whether any
   candidate trusted service is in the condition's
   admitted list.

Both helpers are documented inline. The
compute-launch registry (`registry.go`) is
external data — adding a new vector or a new service
is a struct entry.

## Layout

```
examples/iam-autoscaling-privesc-bypass/
├── README.md
├── main.go                     # CEL — fires on writeup, silent on remediated
├── controls/
│   └── CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001.yaml
├── fixtures/
│   ├── writeup-config/observations/{T1,T2}.json
│   └── remediated-config/observations/{T1,T2}.json
├── z3prove/
│   ├── go.mod
│   ├── registry.go             # 9 known compute-launch vectors
│   └── main.go                 # 3 queries × 2 configs + coverage table
└── expected/
    ├── cel-output.txt
    └── z3-output.txt
```

## Source

"AWS EC2 Auto Scaling Privilege Escalation" — Medium,
July 2022, Edoardo Rosa. The DataScientist /
EMRFullAccess / DenyPrivEscs policies in the fixtures
are paraphrased from the article with synthetic ARNs.

## Where this fits

This is **Iteration 13** of the examples roadmap. Adds
two structural beats:

- **Allow ∧ ¬Deny effective-permission resolution** in
  the matcher template — used here for nine vectors,
  reusable for any future deny-list-vs-allow analysis.
- **Architectural-residual finding**: a query that
  returns SAT *both before and after* the
  remediation, because the remediation does not
  address the underlying architectural issue. This
  isn't a "fix didn't work" — the fix did its job.
  It's "the underlying shape is fragile; the fix
  buys time, not safety."

The remediated config's residual SAT on Finding 2 is
the deepest insight in the iteration series: formal
verification can prove not just the current state's
verdict but also the *durability* of a fix against a
known threat model (here: AWS adding new compute
services).
