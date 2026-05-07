; Query — multi-hop transitive can_assume reachability.
;
; Asks: starting from `developer` (an unprivileged IAM user),
; can the principal reach `admin-role` through a chain of 1, 2,
; or 3 sts:AssumeRole hops?
;
; The closed-world axiom on can_assume restricts the predicate
; to the assumer→target pairs the extractor emitted. Reachability
; over a chain of these edges is the SMT solver's job — the
; extractor only knows individual hops; transitive composition
; is reasoning, not observation.
;
; Z3 + cvc5 cross-check: both must agree. The fixture is small
; enough that finite-model-find decides without timeout.
;
; Verdicts:
;   vulnerable:  3-hop chain developer → onboarding-role
;                 → operator-role → admin-role exists. SAT.
;   remediated:  operator-role's trust no longer admits onboarding-role.
;                 Chain breaks at hop 2. UNSAT.

(declare-const start String)
(declare-const finish String)
(declare-const hop1 String)
(declare-const hop2 String)

(assert (= start "arn:aws:iam::444455556666:user/developer"))
(assert (= finish "arn:aws:iam::444455556666:role/admin-role"))

; Reachability via 1, 2, or 3 hops. Existential quantification
; over intermediate principals is the standard SMT pattern for
; bounded transitive reachability over a binary relation.
(assert (or
  ; 1-hop: direct edge.
  (can_assume start finish)
  ; 2-hop: one intermediate.
  (and (can_assume start hop1) (can_assume hop1 finish))
  ; 3-hop: two intermediates — the multi-hop case the
  ; vulnerable fixture exhibits.
  (and (can_assume start hop1)
       (can_assume hop1 hop2)
       (can_assume hop2 finish))))

(check-sat)
(get-value (start hop1 hop2 finish))
