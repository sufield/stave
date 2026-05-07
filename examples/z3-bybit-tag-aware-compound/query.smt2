; Query — Bybit tag-aware compound (developer wildcard → production)
;
; The pattern that enabled the March 2025 Bybit / Safe{WALLET}
; $1.5B ETH heist. A developer's IAM policy used a prefix
; wildcard `arn:aws:s3:::company-frontend-*` for their dev-
; bucket access. The wildcard incidentally matched the
; production frontend bucket. Compromised dev creds → modify
; app.js in the production bucket → CloudFront serves
; backdoored JavaScript to every user.
;
; The compound:
;
;   1. principal has s3:PutObject (write capability)
;   2. principal has a resource pattern ending in "*"
;      (the wildcard — the actual bybit defect)
;   3. some production-tagged bucket exists
;   4. the wildcard pattern's prefix matches the bucket's ARN
;
; CEL would emit findings for each fact independently — broad
; policy on the developer, production tag on the bucket — but
; never ask whether the developer's wildcard pattern actually
; prefix-matches the production-tagged bucket. The conjunction
; is the security property; the witness names the specific
; (developer, wildcard pattern, production bucket) triple.
;
; SAT  → the bybit shape exists. Witness names the developer,
;        the wildcard pattern, and the production bucket the
;        pattern incidentally matches.
; UNSAT → either no developer has a wildcard pattern, or no
;        production bucket exists whose ARN is prefix-matched
;        by any wildcard pattern.

(declare-const developer String)
(declare-const wildcard_pattern String)
(declare-const prod_bucket String)
(declare-const prefix_part String)

; Step 1: developer is an IAM user with PutObject capability.
(assert (has_type developer "aws_iam_user"))
(assert (has_action developer "s3:PutObject"))

; Step 2: developer's policy has a resource pattern ending
;   in "*". The closed-world axiom restricts has_resource to
;   the developer's actual asserted patterns; this constraint
;   selects the wildcards.
(assert (has_resource developer wildcard_pattern))
(assert (str.suffixof "*" wildcard_pattern))

; Step 3: a production-tagged S3 bucket exists.
(assert (has_type prod_bucket "aws_s3_bucket"))
(assert (has_tag prod_bucket "environment=production"))

; Step 4: the wildcard pattern's stripped prefix is a prefix of
;   the production bucket's ARN. Algebraically:
;     wildcard_pattern = prefix_part ++ "*"
;     str.prefixof(prefix_part, prod_bucket)
;
;   For the bybit-pattern-before fixture:
;     wildcard_pattern = "arn:aws:s3:::company-frontend-*"
;     prefix_part      = "arn:aws:s3:::company-frontend-"
;     prod_bucket      = "arn:aws:s3:::company-frontend-prod"
;     → prefix_part is a prefix of prod_bucket → SAT
;
;   For the bybit-pattern-after fixture (no wildcard
;   pattern remains; only specific ARNs and per-bucket-prefix
;   object globs like ".../prod/*" which don't prefix-match
;   the bucket ARN itself):
;     → no satisfying assignment → UNSAT
(assert (= wildcard_pattern (str.++ prefix_part "*")))
(assert (str.prefixof prefix_part prod_bucket))

(check-sat)
(get-value (developer wildcard_pattern prod_bucket prefix_part))
