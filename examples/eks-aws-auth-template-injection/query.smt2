;; Query: Does the EKS aws-auth identity-mapping template use
;; AccessKeyID, exposing the role to the AccessKeyID-injection
;; primitive?
;;
;; PR-1 generic property projector emits:
;;   has_uses_access_key_id(asset, "true"|"false")
;;
;; SAT  = identity mapping uses AccessKeyID; remediated drops
;;        AccessKeyID from the template
;; UNSAT = template is scoped to non-injectable identifiers
(declare-const cluster String)
(assert (has_uses_access_key_id cluster "true"))
(check-sat)
(get-value (cluster))
