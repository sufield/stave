; IAM-FOOTHOLD-001 — internet-facing role reaches a sensitive resource (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; internet_facing_role / sensitive_resource / can_assume / can_pass / has_access /
; resource_policy_grants). Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in | grep -vF 'model is not available'
;   SAT   + witness (role, mid, res) -> a path exists (FAIL).
;   UNSAT -> no internet-facing role reaches a sensitive resource (PASS).
;
; Bounded to one control hop (direct, or via one assumed/passed role), which
; covers the lab's direct and two-hop cases. `mid` = role itself for the direct
; case. Sound: the relations are total define-fun's, so Z3 cannot invent an edge.

(declare-const role String)
(declare-const mid String)
(declare-const res String)

; one control hop: the role itself, or a role it can assume / pass
(define-fun controls ((a String) (b String)) Bool
  (or (= a b) (can_assume a b) (can_pass a b)))

(assert (internet_facing_role role))
(assert (sensitive_resource res))
(assert (controls role mid))
(assert (or (has_access mid res) (resource_policy_grants res mid)))

(check-sat)
(get-value (role mid res))
