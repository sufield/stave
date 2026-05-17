; Query — Rhino Pattern 1 (Policy Self-Mutation) reachability
;
; Spencer Gietzen's 2018 enumeration of 21 IAM privilege-
; escalation methods groups them into 5 structural patterns.
; Pattern 1 is the family of methods where a principal can
; modify its own effective permissions — create a new policy
; version and activate it, attach an admin policy to itself,
; join a privileged group, drop a permissions boundary.
;
; Rhino enumerated 9 named methods in this pattern (methods
; 1, 2, 7, 8, 9, 10, 11, 12, 13). The companion prover identified
; 4 more (CreatePolicy + Attach pair, Delete + Put inline pair,
; Detach + Attach swap, DeleteRolePermissionsBoundary). The
; structural shape is the same: any one of these actions on a
; wildcard resource gives the holder a way to upgrade their
; own permissions.
;
; The compound query asks Z3 to find a principal with at least
; one Pattern 1 action AND a wildcard resource scope — the SMT
; equivalent of "did Pattern 1 fire on any principal?" The
; the companion example already does this via the go-z3 binding;
; this query does it through file-as-language-boundary so any
; SMT solver consumes the same artefact.
;
; SAT  → at least one principal can self-mutate. Witness names
;        the principal (and the satisfying action / resource).
; UNSAT → no principal in the snapshot has the Pattern 1 shape.
;        Either the actions aren't present, or every Pattern 1
;        action is bound to a specific (non-wildcard) resource.
;
; CEL emits 9-13 separate findings here, one per named method,
; each independently flagged. The compound view — that ANY of
; these methods on ANY principal is the exploit shape Pattern 1
; describes — is what the disjunction-over-actions encodes.

(declare-const principal String)
(declare-const action String)
(declare-const resource String)

; Principal must be an IAM user or role (not a bucket, etc.)
(assert (or
  (has_type principal "aws_iam_user")
  (has_type principal "aws_iam_role")))

; The principal grants at least one Pattern 1 action on its
; effective permission set. The list mirrors the registry in
; examples/iam-21-privesc-5-patterns/z3prove/patterns.go —
; Rhino's 9 named methods plus the 4 the companion prover added.
(assert (has_action principal action))
(assert (or
  ; Rhino's enumeration
  (= action "iam:CreatePolicyVersion")
  (= action "iam:SetDefaultPolicyVersion")
  (= action "iam:AttachUserPolicy")
  (= action "iam:AttachGroupPolicy")
  (= action "iam:AttachRolePolicy")
  (= action "iam:PutUserPolicy")
  (= action "iam:PutGroupPolicy")
  (= action "iam:PutRolePolicy")
  (= action "iam:AddUserToGroup")
  ; Beyond Rhino — same structural shape
  (= action "iam:CreatePolicy")
  (= action "iam:DetachUserPolicy")
  (= action "iam:DeleteUserPolicy")
  (= action "iam:DeleteRolePermissionsBoundary")))

; And the action is granted on a wildcard resource — the
; necessary piece that turns the action from "I can manage
; my own scoped policy" into "I can attach AdministratorAccess
; to myself."
(assert (has_resource principal resource))
(assert (= resource "*"))

(check-sat)
(get-value (principal action resource))
