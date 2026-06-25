; ALB-ROUTING-008 — NLB shares instances with a gated ALB (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; alb_target_instance / nlb_target_instance / alb_has_security_controls).
; Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> an NLB reaches an instance behind a gated ALB (FAIL).
;   UNSAT -> no shared instance (PASS).
;
; Quantifier-free: one instance reached by both an NLB and a gated ALB.

(declare-const nlb String)
(declare-const alb String)
(declare-const inst String)

(assert (nlb_target_instance nlb inst))
(assert (alb_target_instance alb inst))
(assert (alb_has_security_controls alb))

(check-sat)
(get-value (nlb alb inst))
