;; Query: Is there a CloudTrail trail that is not currently
;; logging?
;;
;; PR-1 generic property projector emits:
;;   has_logging_enabled(trail, "true"|"false")
;;
;; SAT  = at least one trail has been stopped
;; UNSAT = every trail is logging (the management-events
;;         is_logging boolean is true)
(declare-const trail String)
(assert (has_type trail "aws_cloudtrail_trail"))
(assert (has_logging_enabled trail "false"))
(check-sat)
(get-value (trail))
