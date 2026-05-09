;; Query: Does any cluster role have writable webhook-config
;; (mutating/validating admission webhooks) access?
;;
;; PR-1 generic property projector emits:
;;   has_webhook_config_access(asset, "true"|"false")
;;
;; SAT  = a cluster role grants create/update/patch/delete on
;;        webhook configs (admission persistence primitive)
;; UNSAT = read-only access; no persistence primitive
(declare-const cluster String)
(assert (has_webhook_config_access cluster "true"))
(check-sat)
(get-value (cluster))
