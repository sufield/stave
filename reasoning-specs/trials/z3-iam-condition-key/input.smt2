; Stave SIR facts export — SMT-LIB v2
; FM-060: IAM Condition Key Complexity — deny bypass worked example
;
; Scenario: role/DataProcessor has two IAM policy statements:
;   stmt 0 (Allow): ArnLike aws:PrincipalArn "arn:aws:iam::*:role/*"
;   stmt 1 (Deny):  StringNotLike aws:PrincipalArn "arn:aws:iam::*:role/Admin*"
;
; The Deny uses StringNotLike, which denies principals NOT matching
; "Admin*". This means Admin* principals are EXCLUDED from the deny
; (the deny does not fire for them), while the Allow's ArnLike
; still matches them. Net effect: Admin* roles bypass the Deny.
;
; Expected: SAT — a principal ARN matching "Admin*" threads the needle.
(set-logic QF_S)

; --- Per-statement facts ---
; Ternary predicates: (principal, stmt_index_str, value)
; stmt_index encoded as string for uniform (String, String, String) arity.

(declare-fun stmt_effect (String String String) Bool)
(declare-fun stmt_condition (String String String) Bool)
(declare-fun stmt_action (String String String) Bool)
(declare-fun stmt_resource (String String String) Bool)

; Binary predicates (existing projector output)
(declare-fun has_condition (String String) Bool)
(declare-fun has_condition_value (String String) Bool)
(declare-fun has_type (String String) Bool)

; --- Ground atoms ---

;; Principal and asset type
(assert (has_type "arn:aws:iam::123456789012:role/DataProcessor" "aws_iam_role"))

;; Statement 0: Allow with ArnLike on aws:PrincipalArn
(assert (stmt_effect "arn:aws:iam::123456789012:role/DataProcessor" "0" "Allow"))
(assert (stmt_action "arn:aws:iam::123456789012:role/DataProcessor" "0" "s3:GetObject"))
(assert (stmt_resource "arn:aws:iam::123456789012:role/DataProcessor" "0" "arn:aws:s3:::data-lake/*"))
(assert (stmt_condition "arn:aws:iam::123456789012:role/DataProcessor" "0" "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/*"))

;; Statement 1: Deny with StringNotLike on aws:PrincipalArn
(assert (stmt_effect "arn:aws:iam::123456789012:role/DataProcessor" "1" "Deny"))
(assert (stmt_action "arn:aws:iam::123456789012:role/DataProcessor" "1" "s3:GetObject"))
(assert (stmt_resource "arn:aws:iam::123456789012:role/DataProcessor" "1" "arn:aws:s3:::data-lake/*"))
(assert (stmt_condition "arn:aws:iam::123456789012:role/DataProcessor" "1" "StringNotLike:aws:PrincipalArn=arn:aws:iam::*:role/Admin*"))

;; Existing binary predicates (what the current projector emits)
(assert (has_condition "arn:aws:iam::123456789012:role/DataProcessor" "ArnLike:aws:PrincipalArn"))
(assert (has_condition "arn:aws:iam::123456789012:role/DataProcessor" "StringNotLike:aws:PrincipalArn"))
(assert (has_condition_value "arn:aws:iam::123456789012:role/DataProcessor" "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/*"))
(assert (has_condition_value "arn:aws:iam::123456789012:role/DataProcessor" "StringNotLike:aws:PrincipalArn=arn:aws:iam::*:role/Admin*"))

; --- Closed-world axioms ---

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_effect x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "0") (= z "Allow"))
          (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "1") (= z "Deny"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_condition x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "0") (= z "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/*"))
          (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "1") (= z "StringNotLike:aws:PrincipalArn=arn:aws:iam::*:role/Admin*"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_action x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "0") (= z "s3:GetObject"))
          (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "1") (= z "s3:GetObject"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_resource x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "0") (= z "arn:aws:s3:::data-lake/*"))
          (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "1") (= z "arn:aws:s3:::data-lake/*"))))))

(assert (forall ((x String) (y String))
  (=> (has_condition x y)
      (and (= x "arn:aws:iam::123456789012:role/DataProcessor")
           (or (= y "ArnLike:aws:PrincipalArn")
               (= y "StringNotLike:aws:PrincipalArn"))))))

(assert (forall ((x String) (y String))
  (=> (has_condition_value x y)
      (and (= x "arn:aws:iam::123456789012:role/DataProcessor")
           (or (= y "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/*")
               (= y "StringNotLike:aws:PrincipalArn=arn:aws:iam::*:role/Admin*"))))))

(assert (forall ((x String) (y String))
  (=> (has_type x y)
      (and (= x "arn:aws:iam::123456789012:role/DataProcessor") (= y "aws_iam_role")))))

; --- Query: Q2 — Deny bypass detection ---
;
; Is there a request-context value for aws:PrincipalArn that:
;   (a) matches the Allow's ArnLike pattern "arn:aws:iam::*:role/*"
;   (b) does NOT match the Deny's StringNotLike trigger
;
; StringNotLike "Admin*" means the Deny fires for principals NOT
; matching "Admin*". So the Deny does NOT fire when the principal
; DOES match "Admin*". We look for a value that:
;   - matches ArnLike "arn:aws:iam::*:role/*"       (Allow fires)
;   - matches "arn:aws:iam::*:role/Admin*"           (Deny does NOT fire)
;
; Encoding: ArnLike uses ":" as segment separator, "*" = .* within segment.
; "arn:aws:iam::*:role/*" → arn:aws:iam::<any>:role/<any>
; "Admin*" suffix on the role name → role name starts with "Admin"

(declare-const caller_arn String)

; Allow condition: ArnLike "arn:aws:iam::*:role/*"
; Matches any string of the form arn:aws:iam::<account>:role/<name>
(assert (str.in_re caller_arn
  (re.++ (str.to_re "arn:aws:iam::")
         (re.+ (re.range "0" "9"))     ; account id: one or more digits
         (str.to_re ":role/")
         (re.+ (re.union (re.range "A" "Z") (re.range "a" "z")
                         (re.range "0" "9") (str.to_re "-") (str.to_re "_"))))))

; Deny evasion: the principal's role name starts with "Admin"
; (StringNotLike excludes "Admin*" from the deny, so Admin* evades it)
(assert (str.in_re caller_arn
  (re.++ (str.to_re "arn:aws:iam::")
         (re.+ (re.range "0" "9"))
         (str.to_re ":role/Admin")
         (re.* (re.union (re.range "A" "Z") (re.range "a" "z")
                         (re.range "0" "9") (str.to_re "-") (str.to_re "_"))))))

(check-sat)
(get-value (caller_arn))
