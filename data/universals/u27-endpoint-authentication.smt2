; ============================================================================
; U27 — Non-Public Endpoint Without Authentication
; ============================================================================
;
; ∀ endpoint e where accepts_requests(e) ∧ ¬intent_public(e):
;   ¬requires_auth(e) → FINDING(high, "unauthenticated non-public endpoint")
;
; Every endpoint that accepts requests and is not intentionally public
; must require authentication. Covers API Gateway, ALB, database
; endpoints, function URLs, and every other service that exposes
; a network-accessible interface.
;
; The intent_public qualifier excludes resources deliberately
; configured for public access (S3 static websites, public
; CloudFront distributions).
;
; Encoding: negation — find an endpoint that accepts requests, is
; not intentionally public, and does not require authentication.
;   sat  → violation: unauthenticated non-public endpoint
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Endpoint 0)

; Predicates
(declare-fun accepts_requests (Endpoint) Bool)
(declare-fun intent_public (Endpoint) Bool)
(declare-fun requires_auth (Endpoint) Bool)

; SNAPSHOT INSERTION POINT
; stave grounds these from obs.v0.1 endpoint observations.
; The endpoint→resource mapping resolves at grounding time:
; each endpoint observation carries its resource context.

(push 1)
(declare-const u27_e Endpoint)
(assert (accepts_requests u27_e))
(assert (not (intent_public u27_e)))
(assert (not (requires_auth u27_e)))
(echo "U27: Unauthenticated non-public endpoint")
(check-sat)
(pop 1)

(exit)
