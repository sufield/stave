; ============================================================================
; U29 — Stateful Resource Without Backup
; ============================================================================
;
; ∀ resource r where stores_data(r):
;   ¬has_backup(r) → FINDING(medium, "stateful resource lacks backup")
;
; Every resource that stores persistent data must have backup
; configured. Covers automated snapshots, AWS Backup plans, and
; point-in-time recovery — any mechanism that enables data recovery.
;
; Part of the stateful-resource integrity family:
;   U7:  must be encrypted at rest
;   U28: must resist accidental deletion
;   U29: must have backup configured
;
; Encoding: negation — find a resource that stores data but has
; no backup configured.
;   sat  → violation
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Resource 0)

; Predicates — stores_data reused from U7
(declare-fun stores_data (Resource) Bool)
(declare-fun has_backup (Resource) Bool)

; SNAPSHOT INSERTION POINT

(push 1)
(declare-const u29_r Resource)
(assert (stores_data u29_r))
(assert (not (has_backup u29_r)))
(echo "U29: Stateful resource lacks backup")
(check-sat)
(pop 1)

(exit)
