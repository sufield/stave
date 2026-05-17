; Query — Rhino Pattern 2 (Credential Creation / Theft) reachability
;
; Pattern 2 is the family of methods where a principal creates
; or hijacks credentials for a more privileged principal —
; without modifying any policy. Rhino's named methods 4, 5, 6,
; 14: CreateAccessKey, CreateLoginProfile, UpdateLoginProfile,
; UpdateAssumeRolePolicy. The companion go-z3 prover added MFA-virtual-
; device methods, MFA-deactivation, sts:GetFederationToken — all
; same shape: actions that issue or reset credentials.
;
; SAT  → at least one principal has a Pattern 2 action on a
;        wildcard resource. Witness names principal + action.
; UNSAT → no Pattern 2 action present on a wildcard resource.

(declare-const principal String)
(declare-const action String)
(declare-const resource String)

(assert (or
  (has_type principal "aws_iam_user")
  (has_type principal "aws_iam_role")))

(assert (has_action principal action))
(assert (or
  ; Rhino's enumeration
  (= action "iam:CreateAccessKey")
  (= action "iam:CreateLoginProfile")
  (= action "iam:UpdateLoginProfile")
  (= action "iam:UpdateAssumeRolePolicy")
  ; Beyond Rhino — same structural shape
  (= action "iam:CreateVirtualMFADevice")
  (= action "iam:EnableMFADevice")
  (= action "iam:DeactivateMFADevice")
  (= action "sts:GetFederationToken")))

(assert (has_resource principal resource))
(assert (= resource "*"))

(check-sat)
(get-value (principal action resource))
