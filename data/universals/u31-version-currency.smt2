; ============================================================================
; U31 — Software Running Deprecated/EOL Version
; ============================================================================
;
; ∀ resource r where has_managed_version(r):
;   deprecated(version(r)) ∨ eol(version(r))
;   → FINDING(medium, "deprecated or end-of-life software version")
;
; Every resource with a customer-selectable version must not run
; deprecated or end-of-life software. Covers database engine versions,
; runtime versions, Kubernetes versions, and message broker versions.
;
; The version reference data comes from the deprecation calendar
; (data/deprecation-calendar.yaml), not from the observation.
;
; Encoding: negation — find a resource with a managed version that
; is deprecated or EOL.
;   sat  → violation
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Resource 0)

; Predicates
(declare-fun has_managed_version (Resource) Bool)
(declare-fun version_deprecated (Resource) Bool)
(declare-fun version_eol (Resource) Bool)

; SNAPSHOT INSERTION POINT
; stave grounds version_deprecated and version_eol by joining
; the observed version against data/deprecation-calendar.yaml.

(push 1)
(declare-const u31_r Resource)
(assert (has_managed_version u31_r))
(assert (or (version_deprecated u31_r)
            (version_eol u31_r)))
(echo "U31: Deprecated or EOL software version")
(check-sat)
(pop 1)

(exit)
