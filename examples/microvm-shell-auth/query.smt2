; MICROVM shell-auth — does an unauthorized (non-break-glass) role hold shell
; access? (Z3 / SMT). Append after a generated facts.smt2 (closed-world
; define-fun for role_permission / role_break_glass over the scenario's role).
; Cross-check of the Soufflé verdict.
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT -> unauthorized shell access exists (FAIL).  UNSAT -> none (PASS).
; Severity (HIGH vs CRITICAL) is the agent/cicd split; the run harness reads it
; from the same facts, so both engines agree on existence AND tier.

(declare-const role String)
(define-fun has_shell ((r String)) Bool
  (or (role_permission r "lambda" "CreateMicrovmShellAuthToken")
      (role_permission r "lambda" "*")))      ; wildcard includes shell
(assert (has_shell role))
(assert (not (role_break_glass role)))
(check-sat)
(get-value (role))
