; SCIM-004 — SCIM provisioning takeover (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; scim_endpoint_public / scim_handler_serves_api / scim_handler_overprivileged /
; scim_token_reachable). Independent cross-check of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> public endpoint + overprivileged handler + reachable token (FAIL).
;   UNSAT -> at least one condition is false (PASS).
;
; Quantifier-free: one (api, lambda, role, token, path) witness.

(declare-const api String)
(declare-const lam String)
(declare-const role String)
(declare-const tok String)
(declare-const path String)
(declare-const via String)

(assert (scim_endpoint_public api path))
(assert (scim_handler_serves_api lam api))
(assert (scim_handler_overprivileged lam role))
(assert (scim_token_reachable tok via))

(check-sat)
(get-value (api lam tok))
