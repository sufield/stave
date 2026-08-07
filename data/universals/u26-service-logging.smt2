; ============================================================================
; U26 — Service-Level Logging Not Enabled
; ============================================================================
;
; ∀ resource r where generates_security_events(r):
;   ¬logging_enabled(r) → FINDING(high, "service logging disabled")
;
; Every AWS service that generates security-relevant events beyond
; CloudTrail management events must have its service-specific logging
; enabled (S3 access logs, RDS audit logs, VPC flow logs, etc.).
;
; Fills the gap between U14 (region-level CloudTrail) and U15
; (detection pipeline delivery): U26 covers the middle layer where
; service-specific logs originate.
;
; Encoding: negation — find a resource that generates events but
; does not have logging enabled.
;   sat  → violation: resource with logging disabled
;   unsat → universal holds: all event-generating resources log
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Resource 0)

; Predicates
(declare-fun generates_security_events (Resource) Bool)
(declare-fun logging_enabled (Resource) Bool)

; SNAPSHOT INSERTION POINT
; stave grounds generates_security_events and logging_enabled from obs.v0.1

(push 1)
(declare-const u26_r Resource)
(assert (generates_security_events u26_r))
(assert (not (logging_enabled u26_r)))
(echo "U26: Service logging disabled")
(check-sat)
(pop 1)

(exit)
