; ============================================================================
; U32 — Compute Without IMDSv2
; ============================================================================
;
; ∀ compute c where has_metadata_endpoint(c):
;   ¬enforces_imdsv2(c)
;   → FINDING(high, "metadata endpoint allows v1 — SSRF credential theft risk")
;
; Every compute resource with an instance metadata endpoint must
; enforce IMDSv2 (token-required). IMDSv1 is vulnerable to SSRF-based
; credential theft: an attacker who can make the instance issue an
; HTTP request to 169.254.169.254 can steal the instance role
; credentials.
;
; Currently AWS-specific. The domain predicate has_metadata_endpoint
; can extend to GCP/Azure metadata services.
;
; Encoding: negation — find a compute resource with a metadata
; endpoint that does not enforce IMDSv2.
;   sat  → violation
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort ComputeResource 0)

; Predicates
(declare-fun has_metadata_endpoint (ComputeResource) Bool)
(declare-fun enforces_imdsv2 (ComputeResource) Bool)

; SNAPSHOT INSERTION POINT

(push 1)
(declare-const u32_c ComputeResource)
(assert (has_metadata_endpoint u32_c))
(assert (not (enforces_imdsv2 u32_c)))
(echo "U32: Metadata endpoint allows v1")
(check-sat)
(pop 1)

(exit)
