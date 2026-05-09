;; Query: Does the destination bucket's resource policy grant
;; cross-account access to the source-account ROOT principal,
;; or include broad-read actions beyond the replication API
;; surface?
;;
;; The fixtures (writeup-config / remediated-config) share an
;; identical structured shape; their only meaningful diff lives
;; inside the stringified storage.policy_json field. PR 4
;; lifted Conditions; PR 5 lifts Statement-level Principal and
;; Action through resource_policy_principal /
;; resource_policy_action.
;;
;; Two over-permission shapes:
;;
;;   1. Principal scope:  arn:aws:iam::SRC:root   (any role/user
;;      in the source account can write — including a future
;;      compromised one). Remediation pins the principal to a
;;      single bucket-replication-role.
;;   2. Action scope:     s3:Get* + s3:List*       (read access on
;;      a destination bucket replication never reads from).
;;      Remediation removes the entire AllowRead statement,
;;      leaving only the five replication-required actions.
;;
;; The query is satisfied if EITHER over-permission shape is
;; present. Closed-world axioms make absence-of-fact equivalent
;; to "this principal/action is not granted by the resource
;; policy" — distinct from "this principal/action exists
;; elsewhere".
;;
;; SAT  = the destination bucket's policy is over-permissioned
;;        (root principal OR broad-read actions). Witness names
;;        the bucket and the offending object.
;; UNSAT = the policy grants only the specific replication role
;;        and only the replication-required actions.

(declare-const bucket String)
(declare-const offender String)

(assert (has_type bucket "aws_s3_bucket"))
(assert (or
    (resource_policy_principal bucket "arn:aws:iam::111122223333:root")
    (resource_policy_action bucket "s3:Get*")
    (resource_policy_action bucket "s3:List*")
))
;; Bind 'offender' to whichever object the disjunct matched, so
;; the witness model carries the discriminator value.
(assert (or
    (and (= offender "arn:aws:iam::111122223333:root")
         (resource_policy_principal bucket offender))
    (and (= offender "s3:Get*")  (resource_policy_action bucket offender))
    (and (= offender "s3:List*") (resource_policy_action bucket offender))
))

(check-sat)
(get-value (bucket offender))
