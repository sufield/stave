; AGENT-CHAIN-001 — agent role reaches a sensitive resource (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for agent_role /
; sensitive_resource / can_assume / can_pass / has_access / resource_policy_grants).
; Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT  + witness -> a path exists (FAIL).  UNSAT -> no agent reaches sensitive (PASS).
;
; Bounded to TWO control hops (role -> mid1 -> mid2), covering the direct,
; two-hop, and three-entity (assume + pass) cases in the trap-triplet. Sound:
; the relations are total define-fun's, so Z3 cannot invent an edge.

(declare-const role String)
(declare-const mid1 String)
(declare-const mid2 String)
(declare-const res String)

; one control hop: the role itself, or a role it can assume / pass
(define-fun controls ((a String) (b String)) Bool
  (or (= a b) (can_assume a b) (can_pass a b)))

(assert (agent_role role))
(assert (sensitive_resource res))
(assert (controls role mid1))        ; hop 1 (or identity)
(assert (controls mid1 mid2))        ; hop 2 (or identity)
(assert (or (has_access mid2 res) (resource_policy_grants res mid2)))

(check-sat)
(get-value (role mid1 mid2 res))
