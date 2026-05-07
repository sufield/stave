; Query — anonymous Cognito session reaches IAM-granted S3 access
;
; The chain Z3 reasons over:
;
;   pool   : aws_cognito_identity_pool
;            allows_unauthenticated  ⇒ true
;   pool   : maps_unauth_to → role
;   role   : aws_iam_role
;            has_action       ⇒ "s3:*" or any s3:Get*
;            has_resource     ⇒ any S3 ARN
;
; SAT   → an unauthenticated visitor (no AWS credentials, no
;         Cognito user, no API key — just a network path to the
;         Cognito identity-pool endpoint) can obtain a temporary
;         credential bound to `role`, and that role grants S3
;         access. The witness names the specific (pool, role)
;         pair the chain traverses.
;
; UNSAT → no such chain exists. Either the pool does not allow
;         unauthenticated identities, or the unauth-mapped role
;         has no S3 grant.
;
; CEL evaluates each control independently. CTL.COGNITO.SELFREG.001
; checks the pool's self-registration restriction. CTL.IAM.POLICY.
; RESOURCE.WILDCARD.001 checks the role's policy. Neither
; CEL control fires for the unauth-role-with-narrow-S3-read case
; in the writeup-config — the unauth role grants only s3:GetObject
; on a public bucket. But the COMPOSITION — anyone reaching the
; pool can read S3 — is the security property that matters. This
; query is the first SMT-expressed proof of that composition.

(declare-const pool String)
(declare-const role String)
(declare-const action String)
(declare-const resource String)

; --- Chain step 1: anonymous reachability of the identity pool ---
(assert (allows_unauthenticated pool "true"))
(assert (has_type pool "aws_cognito_identity_pool"))

; --- Chain step 2: identity pool → IAM role mapping ---
(assert (maps_unauth_to pool role))
(assert (has_type role "aws_iam_role"))

; --- Chain step 3: role grants some S3 read action on some
;     S3 resource. The over-approximation (separate has_action /
;     has_resource quantifiers, not a single statement-bound
;     ternary) is acceptable for reachability — the witness
;     names a specific role with both a positive S3 action and
;     a positive S3 resource.
(assert (has_action role action))
(assert (has_resource role resource))
(assert (or (= action "s3:*")
            (= action "s3:GetObject")
            (= action "s3:ListBucket")
            (= action "s3:GetObjectVersion")))
(assert (str.prefixof "arn:aws:s3:::" resource))

(check-sat)
(get-value (pool role action resource))
