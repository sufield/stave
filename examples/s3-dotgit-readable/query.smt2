;; Query: Is there a bucket exposing repo artifacts (.git, .env,
;; etc.) AND publicly readable?
;;
;; PR-1 generic property projector emits:
;;   has_exposed_repo_artifacts(bucket, "true"|"false")
;;   has_public_read(bucket, "true"|"false")
;;
;; SAT  = a bucket has both: artifacts exposed AND public read
;; UNSAT = artifacts removed or public read closed
(declare-const bucket String)
(assert (has_type bucket "aws_s3_bucket"))
(assert (has_exposed_repo_artifacts bucket "true"))
(assert (has_public_read bucket "true"))
(check-sat)
(get-value (bucket))
