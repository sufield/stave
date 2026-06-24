; MICROVM auth-token expiration (Z3). facts.smt2 defines create/constrained/maxv.
; finding = create AND (not constrained OR maxv > 30). SAT = FAIL.
(assert create)
(assert (or (not constrained) (> maxv 30)))
(check-sat)
