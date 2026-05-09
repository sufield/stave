;; Query: Can a principal bypass the Deny policy via iam:PassRole +
;; a compute-launch action onto a role that trusts a compute service?
;;
;; The Iter-13 Capital-One-shape primitive:
;;   - principal has iam:PassRole
;;   - principal has at least one compute-launch action that is NOT
;;     covered by their Deny set
;;   - a target role trusts a compute service the attacker can drive
;;
;; The remediated fixture extends the Deny set to cover the
;; compute-launch actions. The has_deny_action projector
;; (added in cmd/exportsir/facts.go) makes Deny visible to the
;; SMT solver; closed-world axioms restrict has_deny_action to
;; the explicitly-asserted (principal, action) pairs.
;;
;; SAT  = the chain composes — the principal can launch compute
;;        with the dangerous action and Deny does not cover it.
;; UNSAT = every compute-launch action is denied or a leg of the
;;        chain is missing.

(declare-const principal String)
(declare-const target_role String)
(declare-const compute_action String)
(declare-const compute_service String)

(assert (has_type principal "aws_iam_user"))
(assert (has_type target_role "aws_iam_role"))
(assert (has_action principal "iam:PassRole"))
(assert (has_action principal compute_action))
(assert (or (= compute_action "autoscaling:CreateAutoScalingGroup")
            (= compute_action "ec2:RunInstances")
            (= compute_action "ecs:RunTask")
            (= compute_action "codebuild:StartBuild")
            (= compute_action "lambda:CreateFunction")
            (= compute_action "sagemaker:CreateNotebookInstance")
            (= compute_action "glue:CreateJob")))
;; Deny check: the chosen compute action must NOT be in the
;; principal's Deny set (closed-world axiom on has_deny_action).
(assert (not (has_deny_action principal compute_action)))
;; Target role must be assumable by a compute service principal.
(assert (trusts_service target_role compute_service))
(assert (or (= compute_service "ec2.amazonaws.com")
            (= compute_service "lambda.amazonaws.com")
            (= compute_service "ecs-tasks.amazonaws.com")
            (= compute_service "codebuild.amazonaws.com")
            (= compute_service "sagemaker.amazonaws.com")))

(check-sat)
(get-value (principal target_role compute_action compute_service))
