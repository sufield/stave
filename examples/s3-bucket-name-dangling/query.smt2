;; Query: Is there a bucket reference whose target either does
;; not exist or is not owned by the expected account (takeover
;; primitive)?
;;
;; PR-1 generic property projector emits:
;;   has_bucket_exists(asset, "true"|"false")
;;   has_bucket_owned(asset, "true"|"false")
;;
;; SAT  = at least one referenced bucket is dangling
;; UNSAT = every reference resolves to an owned, existing bucket
(declare-const ref String)
(assert (or (has_bucket_exists ref "false")
            (has_bucket_owned ref "false")))
(check-sat)
(get-value (ref))
