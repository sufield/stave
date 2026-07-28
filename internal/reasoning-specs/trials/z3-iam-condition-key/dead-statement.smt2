; Stave SIR facts export — SMT-LIB v2
; FM-060: IAM Condition Key Complexity — dead statement worked example
;
; Scenario: role/RestrictedDeploy has one Allow statement with
;   contradictory conditions on aws:PrincipalArn:
;   - StringEquals "arn:aws:iam::111122223333:role/DeployBot"
;   - StringNotEquals "arn:aws:iam::111122223333:role/DeployBot"
;
; The first requires the principal to be exactly DeployBot.
; The second requires the principal to NOT be DeployBot.
; No request context can satisfy both simultaneously.
;
; Expected: UNSAT — the statement is dead code.
(set-logic QF_S)

; --- Per-statement facts ---
(declare-fun stmt_effect (String String String) Bool)
(declare-fun stmt_condition (String String String) Bool)
(declare-fun stmt_action (String String String) Bool)
(declare-fun stmt_resource (String String String) Bool)

; Binary predicates (existing projector output)
(declare-fun has_condition (String String) Bool)
(declare-fun has_condition_value (String String) Bool)
(declare-fun has_type (String String) Bool)

; --- Ground atoms ---

(assert (has_type "arn:aws:iam::111122223333:role/RestrictedDeploy" "aws_iam_role"))

;; Statement 0: Allow with contradictory conditions
(assert (stmt_effect "arn:aws:iam::111122223333:role/RestrictedDeploy" "0" "Allow"))
(assert (stmt_action "arn:aws:iam::111122223333:role/RestrictedDeploy" "0" "s3:PutObject"))
(assert (stmt_resource "arn:aws:iam::111122223333:role/RestrictedDeploy" "0" "arn:aws:s3:::deploy-bucket/*"))
(assert (stmt_condition "arn:aws:iam::111122223333:role/RestrictedDeploy" "0" "StringEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))
(assert (stmt_condition "arn:aws:iam::111122223333:role/RestrictedDeploy" "0" "StringNotEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))

;; Existing binary predicates
(assert (has_condition "arn:aws:iam::111122223333:role/RestrictedDeploy" "StringEquals:aws:PrincipalArn"))
(assert (has_condition "arn:aws:iam::111122223333:role/RestrictedDeploy" "StringNotEquals:aws:PrincipalArn"))
(assert (has_condition_value "arn:aws:iam::111122223333:role/RestrictedDeploy" "StringEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))
(assert (has_condition_value "arn:aws:iam::111122223333:role/RestrictedDeploy" "StringNotEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))

; --- Closed-world axioms ---

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_effect x y z)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy") (= y "0") (= z "Allow")))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_condition x y z)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy") (= y "0")
           (or (= z "StringEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot")
               (= z "StringNotEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_action x y z)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy") (= y "0") (= z "s3:PutObject")))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_resource x y z)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy") (= y "0") (= z "arn:aws:s3:::deploy-bucket/*")))))

(assert (forall ((x String) (y String))
  (=> (has_condition x y)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy")
           (or (= y "StringEquals:aws:PrincipalArn")
               (= y "StringNotEquals:aws:PrincipalArn"))))))

(assert (forall ((x String) (y String))
  (=> (has_condition_value x y)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy")
           (or (= y "StringEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot")
               (= y "StringNotEquals:aws:PrincipalArn=arn:aws:iam::111122223333:role/DeployBot"))))))

(assert (forall ((x String) (y String))
  (=> (has_type x y)
      (and (= x "arn:aws:iam::111122223333:role/RestrictedDeploy") (= y "aws_iam_role")))))

; --- Query: Q1 — Dead statement detection ---
;
; Can any request context satisfy ALL conditions in statement 0?
;
; Condition 1: StringEquals aws:PrincipalArn = "...role/DeployBot"
;   → caller_arn MUST equal the exact string
; Condition 2: StringNotEquals aws:PrincipalArn = "...role/DeployBot"
;   → caller_arn MUST NOT equal the exact string
;
; These are contradictory: (= x V) ∧ (not (= x V)) is always false.

(declare-const caller_arn String)

; Condition 1: StringEquals
(assert (= caller_arn "arn:aws:iam::111122223333:role/DeployBot"))

; Condition 2: StringNotEquals
(assert (not (= caller_arn "arn:aws:iam::111122223333:role/DeployBot")))

(check-sat)
; Expected: unsat
