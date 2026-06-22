# E2E Test: IAM PassRole service-mediated escalation cluster (Lambda / Glue / SSM / DataPipeline)

## Case summary

- **Pattern**: `iam:PassRole` combined with a service action that executes
  attacker-controlled code or commands under the passed role. Extends the
  already-shipped PassRole pivots (CloudFormation CreateStack, EC2
  RunInstances, CodeBuild StartBuild) to four additional services:
  Lambda (`lambda:CreateFunction`), Glue (`glue:CreateDevEndpoint`), SSM
  (`ssm:SendCommand` / `ssm:StartSession` on an already-running
  broader-role instance), and DataPipeline (`datapipeline:CreatePipeline` +
  `datapipeline:ActivatePipeline`).
- **Per-service controls, not generalized.** The "one control per service
  action" decision made during the CloudFormation iteration applies
  uniformly — each service has its own remediation path and diagnostic
  context.
- **Multi-step preconditions folded upstream.** Lambda's
  CreateFunction + invocation path and DataPipeline's CreatePipeline +
  ActivatePipeline are rolled into each `.present` boolean by the
  extractor; the diagnostic fields (`invocation_vector`,
  `has_activate_permission`) expose which sub-conditions held.

## Assets

| Principal | Technique populated | Fires |
|---|---|---|
| `alice-lambda` | `passrole_createfunction.present = true` (invocation_vector=invoke_function, runtime=python3.12) | ✅ `PASSROLE.CREATEFUNCTION.001` |
| `bob-glue` | `passrole_createdevendpoint.present = true` (endpoint_type=standard) | ✅ `PASSROLE.CREATEDEVENDPOINT.001` |
| `carol-ssm` | `passrole_sendcommand.present = true` (invocation_method=send_command, target_instance populated) | ✅ `PASSROLE.SENDCOMMAND.001` |
| `dave-datapipeline` | `passrole_createpipeline.present = true` (has_activate_permission=true) | ✅ `PASSROLE.CREATEPIPELINE.001` |
| `eve-clean` | every technique `.present = false` | — |
| `some-service-role` | `kind = role` + all four techniques `.present = true` | ✅ all four `PASSROLE.*` controls (role-side coverage — kind gate lifted) |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001` | high | `passrole_createfunction.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001` | high | `passrole_createdevendpoint.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001` | high | `passrole_sendcommand.present=true` (any principal kind) | 2 |
| `CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001` | high | `passrole_createpipeline.present=true` (any principal kind) | 2 |
| **Total** | | | **8** |

## Expected result

- Exit code: 3
- Findings: 8
- Assets evaluated: 6, unsafe: 5 (four failing users plus the role, which fires all four controls)

## Notes

Severity is `high` across the family, matching the existing PASSROLE.*
convention (CREATESTACK, RUNINSTANCES, STARTBUILD all at high with
`base_impact: 9` and `blast_radius.multiplier: 2.0`). The earlier
Cluster 1 / Cluster 2 direct self-escalation controls sit at `critical`
because they're one-step paths to admin on self; the PassRole pivots
require the target service to execute the attacker's code, which is
operationally one more step and has been sized accordingly.

`invocation_vector` on the Lambda technique documents which path
(InvokeFunction, function URL, or a trigger wiring) made the created
function reachable. This is diagnostic context — the predicate does
not branch on it — but the operator needs it to know which permission
to remove during remediation.

The SSM technique is a slight departure from the pure "PassRole +
service action" shape — the target instance typically already exists
with its profile attached, so PassRole is not strictly needed at
SendCommand time. The control still sits in the PASSROLE.* family
because the task framed it there and the Rhino publication treats it
as a PassRole-adjacent pivot; the diagnostic `target_instance` field
pins the specific instance involved.

The fixture snapshots have no `generated_by.source_type`, which Stave accepts
by default — matching every other escalation fixture.
