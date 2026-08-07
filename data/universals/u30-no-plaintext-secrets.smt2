; ============================================================================
; U30 — Plaintext Secrets in Configuration
; ============================================================================
;
; ∀ config c where has_credential_field(c):
;   ¬references_secret_manager(c)
;   → FINDING(high, "plaintext secret in configuration")
;
; Configuration that contains credential fields (passwords, tokens,
; private keys) must reference a secret manager (Secrets Manager,
; SSM Parameter Store SecureString, Vault) rather than embedding
; plaintext values.
;
; Complements U4/U18 (credential lifetime) — those cover rotation;
; U30 covers storage.
;
; Encoding: negation — find a config with a credential field that
; does not reference a secret manager.
;   sat  → violation: plaintext secret
;   unsat → universal holds
; ============================================================================

(set-logic ALL)
(set-option :produce-models true)

(declare-sort Config 0)

; Predicates
(declare-fun has_credential_field (Config) Bool)
(declare-fun references_secret_manager (Config) Bool)

; SNAPSHOT INSERTION POINT
; stave grounds has_credential_field from obs.v0.1 properties
; that carry password/token/key fields.

(push 1)
(declare-const u30_c Config)
(assert (has_credential_field u30_c))
(assert (not (references_secret_manager u30_c)))
(echo "U30: Plaintext secret in configuration")
(check-sat)
(pop 1)

(exit)
