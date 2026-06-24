; TAG-INTEGRITY-001 (Z3). facts define the four *_holds booleans. The scheme is
; complete iff all four hold. We assert completeness: SAT = complete (PASS),
; UNSAT = NOT complete (FAIL).
(declare-const scheme_complete Bool)
(assert (= scheme_complete (and l_001 l_002 l_rcp l_003)))
(assert scheme_complete)
(check-sat)
