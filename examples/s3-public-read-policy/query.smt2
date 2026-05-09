;; Query: Is there a bucket with public read access AND no
;; Public Access Block?
;;
;; PR-1 generic property projector emits:
;;   has_public_read(bucket, "true"|"false")
;;   has_public_access_blocked(bucket, "true"|"false")
;;
;; SAT  = anonymous READ exposure on an unguarded bucket
;; UNSAT = either public-read cleared or PAB enforced
(declare-const bucket String)
(assert (has_type bucket "aws_s3_bucket"))
(assert (has_public_read bucket "true"))
(assert (has_public_access_blocked bucket "false"))
(check-sat)
(get-value (bucket))
