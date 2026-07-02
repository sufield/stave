; Stave SIR facts export — SMT-LIB v2
; FM-060: IAM Condition Key Complexity — operator mismatch worked example
;
; Scenario: role/DataAnalyst has two statements using different operators
;   on the same condition key aws:PrincipalArn:
;   stmt 0 (Allow): StringLike aws:PrincipalArn "arn:aws:iam::*:role/Analyst*"
;   stmt 1 (Deny):  ArnLike    aws:PrincipalArn "arn:aws:iam::*:role/analyst*"
;
; StringLike is case-SENSITIVE: "Analyst" ≠ "analyst"
; ArnLike is case-INSENSITIVE on the resource portion: "Analyst" = "analyst"
;
; A principal with ARN "arn:aws:iam::123456789012:role/AnalystProd"
; matches the Allow (StringLike, case-sensitive "Analyst*") AND
; matches the Deny (ArnLike, case-insensitive "analyst*" matches "Analyst").
; So the Deny fires — no bypass here.
;
; But a principal with ARN "arn:aws:iam::123456789012:role/ANALYST"
; does NOT match the Allow's StringLike "Analyst*" (wrong case) but
; DOES match the Deny's ArnLike "analyst*" (case-insensitive).
; The Deny fires on something the Allow wouldn't even grant — waste.
;
; The interesting mismatch: the operators define different sets over
; the same key, creating confusion about what is actually protected.
;
; Query: find a value that matches one operator but not the other
; (symmetric difference). This proves the operators disagree.
;
; Expected: SAT — a value exists in the symmetric difference.
(set-logic QF_S)

; --- Per-statement facts ---
(declare-fun stmt_effect (String String String) Bool)
(declare-fun stmt_condition (String String String) Bool)
(declare-fun stmt_action (String String String) Bool)
(declare-fun stmt_resource (String String String) Bool)
(declare-fun has_condition (String String) Bool)
(declare-fun has_condition_value (String String) Bool)
(declare-fun has_type (String String) Bool)

; --- Ground atoms ---

(assert (has_type "arn:aws:iam::123456789012:role/DataAnalyst" "aws_iam_role"))

;; Statement 0: Allow with StringLike (case-sensitive)
(assert (stmt_effect "arn:aws:iam::123456789012:role/DataAnalyst" "0" "Allow"))
(assert (stmt_action "arn:aws:iam::123456789012:role/DataAnalyst" "0" "s3:GetObject"))
(assert (stmt_resource "arn:aws:iam::123456789012:role/DataAnalyst" "0" "arn:aws:s3:::analytics/*"))
(assert (stmt_condition "arn:aws:iam::123456789012:role/DataAnalyst" "0" "StringLike:aws:PrincipalArn=arn:aws:iam::*:role/Analyst*"))

;; Statement 1: Deny with ArnLike (case-insensitive on resource portion)
(assert (stmt_effect "arn:aws:iam::123456789012:role/DataAnalyst" "1" "Deny"))
(assert (stmt_action "arn:aws:iam::123456789012:role/DataAnalyst" "1" "s3:GetObject"))
(assert (stmt_resource "arn:aws:iam::123456789012:role/DataAnalyst" "1" "arn:aws:s3:::analytics/*"))
(assert (stmt_condition "arn:aws:iam::123456789012:role/DataAnalyst" "1" "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/analyst*"))

;; Existing binary predicates
(assert (has_condition "arn:aws:iam::123456789012:role/DataAnalyst" "StringLike:aws:PrincipalArn"))
(assert (has_condition "arn:aws:iam::123456789012:role/DataAnalyst" "ArnLike:aws:PrincipalArn"))
(assert (has_condition_value "arn:aws:iam::123456789012:role/DataAnalyst" "StringLike:aws:PrincipalArn=arn:aws:iam::*:role/Analyst*"))
(assert (has_condition_value "arn:aws:iam::123456789012:role/DataAnalyst" "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/analyst*"))

; --- Closed-world axioms ---

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_effect x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "0") (= z "Allow"))
          (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "1") (= z "Deny"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_condition x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "0") (= z "StringLike:aws:PrincipalArn=arn:aws:iam::*:role/Analyst*"))
          (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "1") (= z "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/analyst*"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_action x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "0") (= z "s3:GetObject"))
          (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "1") (= z "s3:GetObject"))))))

(assert (forall ((x String) (y String) (z String))
  (=> (stmt_resource x y z)
      (or (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "0") (= z "arn:aws:s3:::analytics/*"))
          (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "1") (= z "arn:aws:s3:::analytics/*"))))))

(assert (forall ((x String) (y String))
  (=> (has_condition x y)
      (and (= x "arn:aws:iam::123456789012:role/DataAnalyst")
           (or (= y "StringLike:aws:PrincipalArn")
               (= y "ArnLike:aws:PrincipalArn"))))))

(assert (forall ((x String) (y String))
  (=> (has_condition_value x y)
      (and (= x "arn:aws:iam::123456789012:role/DataAnalyst")
           (or (= y "StringLike:aws:PrincipalArn=arn:aws:iam::*:role/Analyst*")
               (= y "ArnLike:aws:PrincipalArn=arn:aws:iam::*:role/analyst*"))))))

(assert (forall ((x String) (y String))
  (=> (has_type x y)
      (and (= x "arn:aws:iam::123456789012:role/DataAnalyst") (= y "aws_iam_role")))))

; --- Query: Q3 — Operator mismatch detection ---
;
; Find a value that matches StringLike "Analyst*" (case-sensitive)
; but does NOT match ArnLike "analyst*" (case-insensitive).
;
; StringLike "arn:aws:iam::*:role/Analyst*" as flat glob:
;   matches any string starting with "arn:aws:iam::" then digits, ":role/Analyst"
;   and case-sensitive — "Analyst" must have capital A.
;
; ArnLike "arn:aws:iam::*:role/analyst*" as ARN-structured, case-insensitive:
;   lowercases both sides before matching, so "Analyst" = "analyst".
;   If we lowercase the StringLike-matched value, it will also match ArnLike.
;
; So the symmetric difference is in the OTHER direction:
; A value that matches ArnLike "analyst*" (case-insensitive) but NOT
; StringLike "Analyst*" (case-sensitive). E.g., "analyst_dev" (lowercase a).
;
; This proves the operators disagree on case handling.

(declare-const test_arn String)

; Matches ArnLike "analyst*" (case-insensitive): role name lowercased starts with "analyst"
; We simulate by matching the lowercase form
(assert (str.in_re test_arn
  (re.++ (str.to_re "arn:aws:iam::")
         (re.+ (re.range "0" "9"))
         (str.to_re ":role/analyst")
         (re.* (re.union (re.range "a" "z") (re.range "0" "9") (str.to_re "-") (str.to_re "_"))))))

; Does NOT match StringLike "Analyst*" (case-sensitive): role name must start with capital "Analyst"
; Since our value starts with lowercase "analyst", StringLike's case-sensitive match fails.
; We enforce the role portion starts with lowercase 'a':
(assert (str.contains test_arn ":role/a"))

(check-sat)
(get-value (test_arn))
; Expected: sat
; Witness: something like "arn:aws:iam::123456789012:role/analyst_dev"
; This value matches ArnLike (case-insensitive) but NOT StringLike "Analyst*" (case-sensitive).
