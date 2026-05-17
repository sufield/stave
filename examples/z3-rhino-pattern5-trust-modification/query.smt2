; Query — Rhino Pattern 5 (Role Trust Modification) reachability
;
; Pattern 5 is the family of methods where a principal modifies
; a role's trust policy to allow self-assumption — or creates a
; new role whose trust the principal controls. Rhino's named
; method: iam:UpdateAssumeRolePolicy on an admin role. The
; The companion prover added the create-and-assume pair (CreateRole +
; AttachRolePolicy on a fresh role) and the strip-and-assume
; flow (DeleteRolePolicy to widen, then AssumeRole).
;
; This pattern overlaps with Pattern 2 on iam:UpdateAssumeRole-
; Policy — Rhino lists method 14 in both patterns. The compound
; SMT view recovers the overlap deliberately: the disjunction
; doesn't dedupe Rhino's numbering, it captures the structural
; shape "trust-mutation gives the principal a way to assume
; what it couldn't before."
;
; SAT  → principal has at least one trust-modification action
;        on a wildcard resource. Witness names principal + action.
; UNSAT → no Pattern 5 action present.

(declare-const principal String)
(declare-const action String)
(declare-const resource String)

(assert (or
  (has_type principal "aws_iam_user")
  (has_type principal "aws_iam_role")))

(assert (has_action principal action))
(assert (or
  ; Rhino's enumeration (method 14)
  (= action "iam:UpdateAssumeRolePolicy")
  ; Beyond Rhino — same structural shape
  (= action "iam:CreateRole")
  (= action "iam:AttachRolePolicy")
  (= action "iam:DeleteRolePolicy")
  (= action "sts:AssumeRole")))

(assert (has_resource principal resource))
(assert (= resource "*"))

(check-sat)
(get-value (principal action resource))
