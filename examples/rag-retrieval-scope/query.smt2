; RAG-004 — retrieval role reaches data beyond declared sources (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; kb_data_source / retrieval_can_access). Independent cross-check.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> a reachable resource is outside the declared sources (FAIL).
;   UNSAT -> reachable set is contained in declared sources (PASS).
;
; retrieval_can_access already has wildcard prefixes expanded and assume /
; resource-policy edges folded in by the fact generator. Sound: total
; define-fun's, so Z3 cannot invent a reachable resource.

(declare-const res String)
(assert (retrieval_can_access res))
(assert (not (kb_data_source res)))
(check-sat)
(get-value (res))
