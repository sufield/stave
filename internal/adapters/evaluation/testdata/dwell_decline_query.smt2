;; Dwell-grading query: find an asset with a CONFIRMED exposure
;; window — one whose dwell duration is trustworthy enough to grade
;; against an SLA.
;;
;; Append this query to a fact file produced by
;;   stave export-sir --format smt2   (or sirfacts.SerializeSMT2, closed-world)
;; then feed the concatenation to z3 / cvc5.
;;
;; A clamped / zero-dwell exposure window — flagged by the SIR with
;; has_unreliable_exposure_duration because its resolving (secure)
;; observation landed at or before the opening (unsafe) one (clock
;; skew / snapshot reorder) — must NOT qualify. Reading its
;; Start == End as "exposed for 0s, therefore within any SLA" would be
;; unsound, so the grader DECLINES: it excludes windows whose duration
;; the engine deemed untrustworthy, exactly as it declines on a
;; CoverageGap ("we observed unsafe state but cannot trust the
;; duration").
;;
;;   SAT   = a gradeable exposure exists; (get-value (a)) names the asset.
;;   UNSAT = every exposure window is clamped/unreliable -> decline to grade.

(declare-const a String)

(assert (has_type a "aws_s3_bucket"))
(assert (has_exposure_window a "true"))
;; The dwell is trustworthy only when the window is NOT flagged
;; unreliable. Under the closed-world axioms this negation is
;; well-formed: has_unreliable_exposure_duration is false for every
;; asset except those the projection explicitly flagged.
(assert (not (has_unreliable_exposure_duration a "true")))

(check-sat)
(get-value (a))
