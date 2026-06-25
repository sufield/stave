; ALB-ROUTING-002 — auth action shadowed by a higher-precedence rule (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for listener_rule /
; rule_auth / rule_prefix). Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> an auth rule is shadowed (FAIL).  UNSAT -> no shadowing (PASS).
;
; Quantifier-free: an auth rule and a lower-priority-number non-auth rule on the
; same listener whose prefix is a prefix of the auth rule's path. str.prefixof
; with an empty shadow prefix ("" = no path condition) is true for every path.

(declare-const listener String)
(declare-const authr String) (declare-const shadowr String)
(declare-const ap Int) (declare-const sp Int)
(declare-const pAuth String) (declare-const pShadow String)

(assert (listener_rule listener authr ap))
(assert (rule_auth authr))
(assert (listener_rule listener shadowr sp))
(assert (< sp ap))
(assert (not (rule_auth shadowr)))
(assert (distinct authr shadowr))
(assert (rule_prefix authr pAuth))
(assert (rule_prefix shadowr pShadow))
(assert (str.prefixof pShadow pAuth))   ; shadow path subsumes auth path

(check-sat)
(get-value (authr shadowr))
