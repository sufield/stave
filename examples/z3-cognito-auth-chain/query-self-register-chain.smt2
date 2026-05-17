; Query — Cognito self-register → authenticated AWS creds → S3 access
;
; The full chain from the cognito-self-register writeup. Where the
; sibling query z3-cognito-unauth-chain proves a NO-AUTH
; visitor reaches IAM-granted S3 access (open identity pool +
; unauth role with S3 grants), this query proves the SELF-
; REGISTER variant: an internet visitor who registers as a
; new user via the open Cognito user pool, authenticates
; through the app client, and uses the resulting authenticated
; identity to assume the broad auth role.
;
;   1. Cognito user pool with self_registration_unrestricted
;        — anyone on the internet can sign up
;   2. Cognito identity pool that maps_auth_to some IAM role
;        — authenticated identities (including newly-registered
;          ones) are issued temporary credentials for that role
;   3. The mapped IAM role grants broad S3 access
;        (has_action s3:* / s3:Get*  ∧  has_resource *)
;
; This is a four-asset compound across Cognito's user pool,
; identity pool, and IAM role layers. The user pool and
; identity pool aren't directly edge-connected in the SIR —
; the snapshot doesn't carry the app code that wires them
; together — but observing both in the same snapshot, both
; in the unsafe shape, is the security signal that matters.
;
; SAT  → all four conjuncts simultaneously satisfiable in the
;        snapshot. The witness names the specific user pool,
;        identity pool, role, and S3 grant that compose the
;        chain. CEL flags the user pool as unsafe (one
;        finding) and the role as overpermissioned (separate
;        finding); the COMPOSITION — that an internet visitor
;        chains these together — is what this query expresses.
; UNSAT → at least one conjunct fails. Either the user pool
;        restricts self-registration (most common
;        remediation), or the identity pool no longer maps
;        to a broad role, or the role has been scoped.

(declare-const user_pool String)
(declare-const identity_pool String)
(declare-const auth_role String)
(declare-const action String)
(declare-const resource String)

; Step 1: user pool admits self-registration
(assert (has_type user_pool "aws_cognito_user_pool"))
(assert (self_registration_unrestricted user_pool "true"))

; Step 2: identity pool maps authenticated identities to a role
(assert (has_type identity_pool "aws_cognito_identity_pool"))
(assert (maps_auth_to identity_pool auth_role))

; Step 3: that role grants broad S3 access
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
(get-value (user_pool identity_pool auth_role action resource))
