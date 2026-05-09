;; Query: Does a Cognito user pool have MFA disabled OR advanced
;; security disabled?
;;
;; PR-1 generic property projector emits:
;;   has_mfa_enforced(pool, "true"|"false")
;;   has_advanced_security_enabled(pool, "true"|"false")
;; (closed-world: only the explicitly-asserted (pool, value) pairs hold)
;;
;; SAT  = at least one pool is configured insecurely
;; UNSAT = every pool has both MFA and advanced security on
(declare-const pool String)
(assert (has_type pool "aws_cognito_user_pool"))
(assert (or (has_mfa_enforced pool "false")
            (has_advanced_security_enabled pool "false")))
(check-sat)
(get-value (pool))
