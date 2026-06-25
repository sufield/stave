; ALB-ROUTING-006 — inconsistent controls across paths to one backend (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for tg_instance /
; path_to_tg / rule_auth / rule_sourceip / alb_waf). Independent cross-check of
; the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> some instance is reachable by a controlled AND an uncontrolled
;   path (FAIL).  UNSAT -> every path to every backend carries equivalent controls (PASS).
;
; Quantifier-free: two explicit paths (tg/alb/listener/rule) that resolve to the
; same instance, asserted to differ on at least one control. The relations are
; total define-fun's, so Z3 cannot invent a path.

(declare-const inst String)
(declare-const tg1 String) (declare-const a1 String) (declare-const l1 String) (declare-const r1 String)
(declare-const tg2 String) (declare-const a2 String) (declare-const l2 String) (declare-const r2 String)

; two routing paths that reach the same backend instance
(assert (path_to_tg tg1 a1 l1 r1)) (assert (tg_instance tg1 inst))
(assert (path_to_tg tg2 a2 l2 r2)) (assert (tg_instance tg2 inst))
(assert (distinct r1 r2))

; at least one control present on path 1 and absent on path 2
(assert (or
  (and (rule_auth r1)     (not (rule_auth r2)))
  (and (rule_sourceip r1) (not (rule_sourceip r2)))
  (and (alb_waf a1)       (not (alb_waf a2)))))

(check-sat)
(get-value (inst r1 r2))
