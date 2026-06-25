; COGNITO-SSO-005 — ghost identity with elevated privileges (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; pool_has_external_idp / pool_missing_presignup / sensitive_attribute_mapped).
; Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> all three conditions hold for some (pool, idp) (FAIL).
;   UNSAT -> the gate is present or no sensitive mapping (PASS).
;
; Quantifier-free: one (pool, idp, attr, claim) witness.

(declare-const pool String)
(declare-const idp String)
(declare-const attr String)
(declare-const claim String)

(assert (pool_has_external_idp pool idp))
(assert (pool_missing_presignup pool))
(assert (sensitive_attribute_mapped pool idp attr claim))

(check-sat)
(get-value (pool idp attr))
