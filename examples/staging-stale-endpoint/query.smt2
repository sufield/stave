;; Query: Is a non-production-tagged asset also publicly listable?
;;
;; This example ships four fixtures modeling distinct states rather
;; than a vulnerable/remediated pair:
;;
;;   stale-staging         env=staging,    dormant,  not public
;;   active-staging        env=staging,    active,   not public
;;   prod-dormant          env=production, dormant,  not public
;;   stale-staging-public  env=demo,       dormant,  PUBLIC
;;
;; The pure staleness dimension (appears_unused / last_deployment_days)
;; is evaluated by CEL at runtime and surfaces in the SIR export only
;; as the CEL-derived `contributed_by` / `has_exposure_window`
;; predicates. Querying those would be circular — it asks the solver
;; to trust the verdict CEL already reached rather than re-deriving it
;; from configuration data. Per SMT-QUERY-GAPS.md, dormancy is not
;; projected as a raw fact, so the staleness signal alone is not
;; independently solver-decidable here.
;;
;; The COMPOUND dimension, however, IS decidable from raw projected
;; facts. The `staging_endpoint_exposed` chain escalates to HIGH when
;; a non-production resource is also publicly reachable. Both inputs
;; are raw triples the projector emits directly:
;;
;;   has_tag(asset, "environment=<value>")  — properties.*.tags.environment
;;   has_public_list(asset, "true")         — properties.storage.access.public_list
;;
;; So this query asks the compound security question — "does any asset
;; carry a non-production environment tag AND allow public listing?" —
;; and the solver derives the verdict itself.
;;
;; SAT   = a non-production resource is publicly listable (the HIGH
;;         compound exposure the chain detects).
;; UNSAT = no non-production resource is publicly listable.
;;
;; Verdicts (explicit fixture selection — see run.sh):
;;   stale-staging         unsat  (non-prod, but not public)
;;   active-staging        unsat  (non-prod, but not public)
;;   prod-dormant          unsat  (public-less AND production-tagged)
;;   stale-staging-public  sat    (env=demo AND public_list=true)

(declare-const a String)
(assert (or (has_tag a "environment=staging")
            (has_tag a "environment=dev")
            (has_tag a "environment=test")
            (has_tag a "environment=qa")
            (has_tag a "environment=sandbox")
            (has_tag a "environment=demo")
            (has_tag a "environment=poc")
            (has_tag a "environment=prototype")))
(assert (has_public_list a "true"))
(check-sat)
(get-model)
