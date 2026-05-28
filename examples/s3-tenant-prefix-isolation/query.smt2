;; Query: Does any app-signer identity have enforce_prefix=false?
;;
;; The two fixtures (before / after) share an identical structured
;; shape; the only meaningful diff lives inside the stringified
;; `purpose` field on the `appsigner:s3:acme-uploads` identity:
;;
;;   before  purpose=signs_uploads;enforce_prefix=false;allow_traversal=true
;;   after   purpose=signs_uploads;enforce_prefix=true;allow_traversal=false
;;
;; `enforce_prefix=false` is the unsafe state — without per-tenant
;; prefix enforcement, the signer can mint signed URLs that access
;; objects outside the requesting tenant's prefix scope.
;;
;; PR 3.5 added IdentityFact.Properties at the SIR boundary so
;; the identity's `purpose` field survives projection, and extended
;; purposeFlagFacts to walk identities. Each semicolon-delimited
;; key=value pair becomes a `has_purpose_flag(subject, "k=v")`
;; triple — see internal/core/sirfacts/facts.go.
;;
;; SAT  = at least one identity carries the unsafe flag (tenant
;;        isolation is NOT enforced).
;; UNSAT = every identity that declares a `purpose` block has
;;         enforce_prefix=true (tenant isolation enforced).

(declare-const u String)
(assert (has_purpose_flag u "enforce_prefix=false"))
(check-sat)
(get-model)
