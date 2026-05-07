; Query — Rhino Pattern 3 (Compute + PassRole) reachability
;
; Pattern 3 is the family of methods where a principal launches
; or modifies compute that runs with a more privileged role.
; The exploit needs three facts to compose, ON DIFFERENT
; ASSETS — this is the only Rhino pattern that's a compound
; rather than a single-asset disjunction:
;
;   1. attacker has iam:PassRole (must pass a role to the compute)
;   2. attacker has at least one compute-launch action
;      (ec2:RunInstances, lambda:CreateFunction,
;       cloudformation:CreateStack, glue:CreateDevEndpoint, ...)
;   3. some target role exists that trusts a compute service
;      principal (the role the attacker passes)
;
; CEL would emit a PassRole finding on the attacker (one
; per-control), separately enumerate launch actions (one per-
; control), separately flag overpermissioned roles (one per-
; control). The COMPOSITION — that these three findings
; together describe a launch path — is what the SMT query
; captures. The over-approximation: Z3 doesn't bind the launch
; action to its expected serviceTrust (e.g. ec2:RunInstances ↔
; ec2.amazonaws.com); a future tightening would assert that
; binding. For reachability the over-approximation is fine —
; SAT is the correct answer in the rhino-vulnerable fixture.
;
; SAT  → attacker, target_role, launch_action all named.
; UNSAT → no Pattern 3 chain present.

(declare-const attacker String)
(declare-const launch_action String)
(declare-const target_role String)
(declare-const service String)

; Attacker is an IAM principal
(assert (or
  (has_type attacker "aws_iam_user")
  (has_type attacker "aws_iam_role")))

; Attacker holds iam:PassRole
(assert (has_action attacker "iam:PassRole"))

; Attacker holds at least one compute-launch action
(assert (has_action attacker launch_action))
(assert (or
  (= launch_action "ec2:RunInstances")
  (= launch_action "lambda:CreateFunction")
  (= launch_action "lambda:UpdateFunctionCode")
  (= launch_action "lambda:CreateEventSourceMapping")
  (= launch_action "cloudformation:CreateStack")
  (= launch_action "glue:CreateDevEndpoint")
  (= launch_action "glue:UpdateDevEndpoint")
  (= launch_action "datapipeline:CreatePipeline")
  (= launch_action "ecs:RunTask")
  (= launch_action "ecs:CreateService")
  (= launch_action "codebuild:CreateProject")
  (= launch_action "codebuild:StartBuild")
  (= launch_action "sagemaker:CreateNotebookInstance")
  (= launch_action "sagemaker:CreateTrainingJob")
  (= launch_action "batch:SubmitJob")
  (= launch_action "states:CreateStateMachine")
  (= launch_action "apprunner:CreateService")
  (= launch_action "autoscaling:CreateLaunchConfiguration")
  (= launch_action "autoscaling:CreateAutoScalingGroup")))

; Some target role exists in the snapshot that trusts a
; compute / control-plane service principal — the role the
; attacker would pass to the launched compute.
(assert (has_type target_role "aws_iam_role"))
(assert (trusts_service target_role service))
(assert (or
  (= service "ec2.amazonaws.com")
  (= service "lambda.amazonaws.com")
  (= service "ecs-tasks.amazonaws.com")
  (= service "cloudformation.amazonaws.com")
  (= service "glue.amazonaws.com")
  (= service "sagemaker.amazonaws.com")
  (= service "batch.amazonaws.com")
  (= service "states.amazonaws.com")
  (= service "apprunner.amazonaws.com")
  (= service "datapipeline.amazonaws.com")
  (= service "codebuild.amazonaws.com")))

(check-sat)
(get-value (attacker launch_action target_role service))
