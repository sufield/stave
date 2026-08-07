; ============================================================================
; U28 — Stateful Resource Without Deletion Protection
; ============================================================================
;
; ∀ resource r where stores_data(r) ∧ supports_deletion_protection(r):
;   ¬deletion_protected(r)
;   → FINDING(medium, "stateful resource lacks deletion protection")
;
; Every stateful resource that supports deletion protection must
; have it enabled. Same stores_data(r) domain as U7 (encryption),
; narrowed to resources whose service actually offers the feature.
;
; Part of the stateful-resource integrity family:
;   U7:  must be encrypted at rest
;   U28: must resist accidental deletion
;   U29: must have backup configured
;
; Encoding: negation — find a resource that stores data, supports
; deletion protection, but does not have it enabled.
;   sat  → violation
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Resource 0)

; Predicates — stores_data reused from U7
(declare-fun stores_data (Resource) Bool)
(declare-fun supports_deletion_protection (Resource) Bool)
(declare-fun deletion_protected (Resource) Bool)

; SNAPSHOT INSERTION POINT

(push 1)
(declare-const u28_r Resource)
(assert (stores_data u28_r))
(assert (supports_deletion_protection u28_r))
(assert (not (deletion_protected u28_r)))
(echo "U28: Stateful resource lacks deletion protection")
(check-sat)
(pop 1)

(exit)
