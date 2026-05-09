;; Query: Does an IAM user simultaneously have read access to API
;; Gateway + SNS + IAM, with a wildcard resource on at least one
;; of the grants?
;;
;; The compound chain (Iter 14 SNS-secrets-compound-chain article):
;; an attacker who lands on a user with these three capabilities at
;; once can:
;;   1. List API Gateway routes to discover SNS-publishing endpoints
;;   2. Query SNS topic attributes (find subscribed Lambda + secrets)
;;   3. Walk IAM to identify which roles can assume secrets-bearing
;;      identities
;; The cross-service composition is the danger — none of the
;; individual grants is critical in isolation. The remediation in
;; the remediated-config fixture drops apigateway:GET so the chain
;; collapses; SNS / IAM read access alone is the expected
;; operator role.
;;
;; SAT  = the user has all three cross-service reads + wildcard.
;;        The witness names the user.
;; UNSAT = at least one leg of the chain is missing or scoped.

(declare-const user String)

(assert (has_type user "aws_iam_user"))
;; The three cross-service legs
(assert (has_action user "apigateway:GET"))
(assert (has_action user "sns:GetTopicAttributes"))
(assert (has_action user "iam:GetUserPolicy"))
;; Wildcard resource on at least one statement (means at least one
;; of the actions above runs unscoped against any resource)
(assert (has_resource user "*"))

(check-sat)
(get-value (user))
