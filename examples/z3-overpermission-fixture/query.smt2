; Query — IAM resource-wildcard violation reachability
;
; Concatenate this file after a Stave SMT-LIB facts export to ask:
;   "Does any asset have an exposure window in this snapshot
;    contributed by the IAM resource-wildcard control?"
;
; The closed-world axioms emitted by `stave export-sir --format smt2`
; restrict each predicate to be true ONLY for the (subject, object)
; tuples explicitly asserted; they are false everywhere else.
;
; SAT   → at least one asset triggered the control. The
;         fixture is in the unsafe state.
; UNSAT → no asset triggered the control (or the control did not
;         fire on any asset in this fixture). The fixture is in
;         the safe state.
;
; Both `has_exposure_window` and `contributed_by` are baseline
; predicates the serializer always declares, so this query parses
; cleanly against any fact set — including ones where the control
; did not fire.

(declare-const target_asset String)

(assert (has_exposure_window target_asset "true"))
(assert (contributed_by target_asset "CTL.IAM.POLICY.RESOURCE.WILDCARD.001"))

(check-sat)
(get-value (target_asset))
