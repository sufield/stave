; Query — overpermission ∧ compute-assumable (PassRole exploit shape)
;
; The compound an attacker actually exploits when chaining
; iam:PassRole into compute-launch privilege escalation:
;
;   1. role triggered an overpermission finding
;      (CTL.IAM.POLICY.RESOURCE.WILDCARD.001 or similar)
;   2. role's trust policy admits a compute / control-plane
;      service principal (lambda, ec2, ecs, codebuild, glue, …)
;
; Each fact alone is a CEL finding. The conjunction is what
; makes the role exploitable: an overpermissioned role with
; a compute trust is a launchpad — anyone with iam:PassRole +
; the matching service's launch action becomes that role's
; full permission set on the next instance / function / task.
;
; CEL evaluates each unsafe predicate per asset; it doesn't
; ask "are these two unsafe states true on the SAME asset
; AND are the two facts independently dangerous because
; they compose into PassRole exposure?" That composition is
; the security property; the SMT layer makes it expressible.
;
; SAT   → at least one role satisfies both. The witness names
;         the role; the agent / human reviewer can then check
;         which compute service trust enables the chain.
; UNSAT → no role is both overpermissioned AND
;         compute-trusted. The PassRole exploit shape is not
;         present in this snapshot.

(declare-const target String)

; Condition 1 — overpermission finding fired on this role
(assert (contributed_by target "CTL.IAM.POLICY.RESOURCE.WILDCARD.001"))
(assert (has_type target "aws_iam_role"))

; Condition 2 — trust policy admits at least one compute /
; control-plane service principal. The service list here is
; the canonical PassRole-exploitable set: compute and
; deployment automation that an attacker with the right
; launch action can turn into role-execution.
(assert (or
  (trusts_service target "lambda.amazonaws.com")
  (trusts_service target "ec2.amazonaws.com")
  (trusts_service target "ecs-tasks.amazonaws.com")
  (trusts_service target "codebuild.amazonaws.com")
  (trusts_service target "glue.amazonaws.com")
  (trusts_service target "sagemaker.amazonaws.com")
  (trusts_service target "states.amazonaws.com")
  (trusts_service target "cloudformation.amazonaws.com")
))

(check-sat)
(get-value (target))
