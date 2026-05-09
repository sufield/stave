;; Query: Is there a private API Gateway whose Deny block scopes
;; on aws:sourceVpc instead of aws:sourceVpce?
;;
;; The fixtures (writeup-config / remediated-config / broadened-allow)
;; share an identical structured shape; their only meaningful diff
;; lives inside the stringified resource_policy_json field. The
;; stringifiedPolicyFacts projector parses that JSON and re-emits
;; each statement's Condition through has_condition_value.
;;
;;   writeup-config        StringNotEquals:aws:sourceVpc=vpc-…
;;                         (VPC scope leaks public-internet traffic
;;                          via NAT — a "private" API isn't private)
;;   remediated-config     StringNotEquals:aws:sourceVpce=vpce-…
;;                         (only traffic entering through the VPC
;;                          endpoint qualifies — actually private)
;;   broadened-allow       same VPC (not VPCE) condition; still
;;                         vulnerable — sat
;;
;; The query asks whether any API carries a sourceVpc condition;
;; the closed-world axiom on has_condition makes the absence side
;; (no positive fact) report false.
;;
;; SAT  = a private API still scopes via aws:sourceVpc — the
;;        policy claims privacy but admits public-NAT traffic.
;; UNSAT = every API uses aws:sourceVpce (or no Condition at all).

(declare-const api String)

(assert (has_type api "aws_apigateway_rest_api"))
(assert (has_condition api "StringNotEquals:aws:sourceVpc"))

(check-sat)
(get-value (api))
