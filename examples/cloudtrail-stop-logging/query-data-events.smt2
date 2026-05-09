;; Query: Is there a sensitive S3 bucket WITHOUT CloudTrail data
;; event logging coverage?
;;
;; The data-events fixtures (data-events-before / data-events-after):
;;   - vulnerable: bucket tagged data_classification=pii (or
;;     financial / phi) is not listed in any trail's
;;     event_selectors[].data_resources[].values[]
;;   - remediated: the same bucket IS listed; closed-world axiom
;;     on has_data_event_logging reports true for that bucket only
;;
;; The has_data_event_logging projector (added in
;; cmd/exportsir/facts.go) emits one fact per (bucket, "true")
;; pair drawn from event_selectors[].data_resources. A bucket
;; without coverage produces no positive fact and the closed-world
;; axiom restricts the predicate to false elsewhere.
;;
;; SAT  = a sensitive bucket exists with no data event logging.
;;        The witness names the uncovered bucket.
;; UNSAT = every sensitive bucket is in the trail's data_resources.

(declare-const bucket String)
(declare-const tag String)

(assert (has_type bucket "aws_s3_bucket"))
;; Sensitivity: the bucket carries a data-classification tag for
;; one of the three regulated classes.
(assert (has_tag bucket tag))
(assert (or (= tag "data_classification=pii")
            (= tag "data_classification=phi")
            (= tag "data_classification=financial")))
;; Coverage gap: no positive has_data_event_logging fact for this
;; bucket. Under closed-world the negation is well-formed.
(assert (not (has_data_event_logging bucket "true")))

(check-sat)
(get-value (bucket tag))
