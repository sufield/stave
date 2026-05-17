; Query — Cognito authenticated user reaches IAM-granted S3 access
;
; Strips the user-pool / self-registration conjunct from the
; sibling query-self-register-chain.smt2. Asks the simpler
; question: assuming SOMEONE is authenticated against the
; Cognito identity pool — by ANY means: legitimate onboarding,
; SSO, IdP federation, or self-registration — can they reach
; broad S3 access through the mapped auth role?
;
; The chain Z3 reasons over:
;
;   authenticated visitor (any source)
;     → Cognito identity pool with maps_auth_to → IAM role
;     → role grants S3 read/write on a wildcard / S3 resource
;
; SAT on BOTH fixtures of the cognito-self-register-to-
; aws-creds example. That's the pedagogical reveal:
;
;   writeup-config:  user pool open + auth role broad → sat
;   remediated:       user pool restricted + auth role STILL broad → sat
;
; The auth role's permissions don't change between fixtures.
; Only the user pool's self-registration gate changed. So the
; auth-chain query stays SAT — meaning "if someone is
; authenticated, they reach S3 *" — across both. The
; remediation didn't fix the role; it fixed the registration
; gate. The role is still a footgun if any other onboarding
; path admits an attacker.
;
; The companion query-self-register-chain.smt2 adds the
; self_registration_unrestricted predicate; that flips to
; UNSAT on remediated, isolating the registration gate as
; the actual choke point.

(declare-const identity_pool String)
(declare-const auth_role String)
(declare-const action String)
(declare-const resource String)

; Identity pool maps authenticated identities to a role
(assert (has_type identity_pool "aws_cognito_identity_pool"))
(assert (maps_auth_to identity_pool auth_role))

; That role grants broad S3 access
(assert (has_type auth_role "aws_iam_role"))
(assert (has_action auth_role action))
(assert (or
  (= action "s3:*")
  (= action "s3:GetObject")
  (= action "s3:GetObjectVersion")
  (= action "s3:ListBucket")
  (= action "s3:PutObject")
  (= action "s3:DeleteObject")))
(assert (has_resource auth_role resource))
(assert (or
  (= resource "*")
  (str.prefixof "arn:aws:s3:::" resource)))

(check-sat)
(get-value (identity_pool auth_role action resource))
