;; Query: Does the upload signer use prefix-mode (broad write
;; scope) instead of exact-key mode?
;;
;; PR-1 generic property projector emits:
;;   has_upload_key_mode(asset, "prefix"|"exact"|...)
;;
;; SAT  = signer permits broad uploads under a prefix
;; UNSAT = signer is bound to an exact object key
(declare-const signer String)
(assert (has_upload_key_mode signer "prefix"))
(check-sat)
(get-value (signer))
