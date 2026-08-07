; ============================================================================
; U33 — Required Security Service Not Enabled
; ============================================================================
;
; ∀ security_service s ∈ required_detection_services:
;   ¬enabled(s) → FINDING(critical, "required security service not enabled")
;
; Every security service that the organization requires must be
; enabled. The set of required services is organization-defined
; (e.g., CloudTrail, Config, GuardDuty, SecurityHub are typically
; mandatory; Macie, Detective, Inspector are optional).
;
; Precondition to the detection lifecycle:
;   U33: must be enabled
;   U15: must deliver (if configured and enabled)
;   U16: must cover all deployment regions
;
; Encoding: negation — find a required security service that is
; not enabled.
;   sat  → violation
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort DetectionService 0)

; Predicates — detection_enabled reused from U15
(declare-fun in_required_services (DetectionService) Bool)
(declare-fun detection_enabled (DetectionService) Bool)

; SNAPSHOT INSERTION POINT
; in_required_services is grounded from the organization's
; detection policy, not from the observation.

(push 1)
(declare-const u33_s DetectionService)
(assert (in_required_services u33_s))
(assert (not (detection_enabled u33_s)))
(echo "U33: Required security service not enabled")
(check-sat)
(pop 1)

(exit)
