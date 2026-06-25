; BATCH-003 / ECS-003 — escalation chain exists (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for batch_ec2_env /
; imds_accessible / job_role_can_create_jobs / instance_role_data_access /
; instance_role_ecs_wildcard / instance_role_passrole). Independent cross-check
; of the Soufflé verdict.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> the four-condition escalation chain exists (FAIL).
;   UNSAT -> at least one condition is false (PASS).
;
; Quantifier-free: a single (env, job_role, instance_role, resource) witness.
; Sensitive reach = direct data OR ecs:* OR iam:PassRole on the instance role.

(declare-const env String)
(declare-const jobrole String)
(declare-const instrole String)
(declare-const res String)

(assert (batch_ec2_env env instrole))
(assert (imds_accessible env))
(assert (job_role_can_create_jobs env jobrole))
(assert (or (instance_role_data_access instrole res)
            (instance_role_ecs_wildcard instrole)
            (instance_role_passrole instrole)))

(check-sat)
(get-value (env jobrole instrole))
