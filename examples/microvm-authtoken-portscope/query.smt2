; MICROVM auth-token port scoping (Z3). facts.smt2 defines create/port_scoped/
; allows_lifecycle (the collector resolves allowed∩lifecycle into allows_lifecycle).
; finding = create AND (not port_scoped OR allows_lifecycle). SAT = FAIL.
(assert create)
(assert (or (not port_scoped) allows_lifecycle))
(check-sat)
