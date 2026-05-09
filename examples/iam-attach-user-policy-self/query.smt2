;; Query: Does an IAM user grant themselves iam:AttachUserPolicy
;; on their own ARN?
;;
;; The Rhino-21 self-mutation primitive: a user who has
;; iam:AttachUserPolicy with their own ARN as the Resource can
;; attach AdministratorAccess (or any managed policy) to
;; themselves at any time. The grant is fully scoped to the
;; user themselves — it looks innocuous in a per-statement
;; review — but the COMPOSITION (subject == resource on
;; AttachUserPolicy) is the privilege-escalation primitive.
;;
;; SAT  = a user grants themselves AttachUserPolicy. The
;;        witness names the user.
;; UNSAT = no user has the self-targeting AttachUserPolicy
;;        grant.

(declare-const user String)

(assert (has_type user "aws_iam_user"))
(assert (has_action user "iam:AttachUserPolicy"))
;; The dangerous twist: the resource of the AttachUserPolicy
;; grant is the user themselves. With closed-world axioms,
;; (has_resource user user) holds iff there is an explicit
;; (user, user) tuple in the asserted has_resource facts.
(assert (has_resource user user))

(check-sat)
(get-value (user))
