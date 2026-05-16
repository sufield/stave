; Stave SIR facts export — SMT-LIB v2
; Predicates declared as Bool functions over String args.
; Closed-world axioms emitted per predicate: the predicate is true
; ONLY for the (subject, object) pairs explicitly asserted; for
; every other input it is false. This is the standard fact-base
; encoding for SAT/SMT consumers.
; This file contains FACTS ONLY. Append your query (check-sat / get-model / etc.) before invoking the solver.
(set-logic ALL)

; --- Predicate declarations ---
(declare-fun allows_unauthenticated (String String) Bool)
(declare-fun can_assume (String String) Bool)
(declare-fun contributed_by (String String) Bool)
(declare-fun cross_account_assumes (String String) Bool)
(declare-fun first_seen_at (String String) Bool)
(declare-fun has_access_advisor_available (String String) Bool)
(declare-fun has_action (String String) Bool)
(declare-fun has_advanced_security_enabled (String String) Bool)
(declare-fun has_advanced_security_mode (String String) Bool)
(declare-fun has_agent_action_group_count (String String) Bool)
(declare-fun has_agent_guardrail (String String) Bool)
(declare-fun has_agent_iac_managed (String String) Bool)
(declare-fun has_agent_invocation_logging (String String) Bool)
(declare-fun has_agent_lambda_scope_broad (String String) Bool)
(declare-fun has_agent_s3_scope_broad (String String) Bool)
(declare-fun has_bucket_exists (String String) Bool)
(declare-fun has_bucket_owned (String String) Bool)
(declare-fun has_condition (String String) Bool)
(declare-fun has_condition_value (String String) Bool)
(declare-fun has_customer_can_revoke (String String) Bool)
(declare-fun has_data_event_logging (String String) Bool)
(declare-fun has_declared_role_type (String String) Bool)
(declare-fun has_delegated_principal (String String) Bool)
(declare-fun has_delegation_external_principals (String String) Bool)
(declare-fun has_delegation_review_expired (String String) Bool)
(declare-fun has_delegation_scope_exceeded (String String) Bool)
(declare-fun has_delegation_scope_exceeded_for (String String) Bool)
(declare-fun has_deny_action (String String) Bool)
(declare-fun has_deny_resource (String String) Bool)
(declare-fun has_exposed_repo_artifacts (String String) Bool)
(declare-fun has_exposure_window (String String) Bool)
(declare-fun has_forbidden_category (String String) Bool)
(declare-fun has_forbidden_state (String String) Bool)
(declare-fun has_ghost_trigger (String String) Bool)
(declare-fun has_incompatible_categories (String String) Bool)
(declare-fun has_incompatible_pair (String String) Bool)
(declare-fun has_instance_dual_homed (String String) Bool)
(declare-fun has_instance_profile_arn (String String) Bool)
(declare-fun has_instance_profile_overprivileged (String String) Bool)
(declare-fun has_instance_state (String String) Bool)
(declare-fun has_instance_stopped_age_days (String String) Bool)
(declare-fun has_instance_stopped_aged (String String) Bool)
(declare-fun has_instance_vpc (String String) Bool)
(declare-fun has_intent_mismatch (String String) Bool)
(declare-fun has_intent_rationale (String String) Bool)
(declare-fun has_kb_source_encrypted (String String) Bool)
(declare-fun has_kb_target_bucket (String String) Bool)
(declare-fun has_list_via_resource (String String) Bool)
(declare-fun has_logging_enabled (String String) Bool)
(declare-fun has_mfa_enforced (String String) Bool)
(declare-fun has_peering_dns_resolution (String String) Bool)
(declare-fun has_peering_id (String String) Bool)
(declare-fun has_peering_peer_account (String String) Bool)
(declare-fun has_peering_peer_in_org (String String) Bool)
(declare-fun has_peering_peer_vpc (String String) Bool)
(declare-fun has_peering_route_broad (String String) Bool)
(declare-fun has_peering_route_target (String String) Bool)
(declare-fun has_peering_status (String String) Bool)
(declare-fun has_permission_action (String String) Bool)
(declare-fun has_permission_drift_threshold_exceeded (String String) Bool)
(declare-fun has_permission_resource (String String) Bool)
(declare-fun has_privilege_level (String String) Bool)
(declare-fun has_public_access_blocked (String String) Bool)
(declare-fun has_public_list (String String) Bool)
(declare-fun has_public_read (String String) Bool)
(declare-fun has_read_via_resource (String String) Bool)
(declare-fun has_resource (String String) Bool)
(declare-fun has_role_age_days (String String) Bool)
(declare-fun has_severity (String String) Bool)
(declare-fun has_tag (String String) Bool)
(declare-fun has_total_services_accessible (String String) Bool)
(declare-fun has_trigger_lambda_exists (String String) Bool)
(declare-fun has_trigger_type (String String) Bool)
(declare-fun has_type (String String) Bool)
(declare-fun has_unknown_delegated_principal (String String) Bool)
(declare-fun has_unknown_delegation (String String) Bool)
(declare-fun has_unused_service (String String) Bool)
(declare-fun has_unused_service_ratio (String String) Bool)
(declare-fun has_upload_key_mode (String String) Bool)
(declare-fun has_uses_access_key_id (String String) Bool)
(declare-fun has_vendor (String String) Bool)
(declare-fun has_vendor_can_make_public (String String) Bool)
(declare-fun has_vendor_put_bucket_policy (String String) Bool)
(declare-fun has_webhook_config_access (String String) Bool)
(declare-fun is_decommissioned (String String) Bool)
(declare-fun is_provisioned (String String) Bool)
(declare-fun last_seen_at (String String) Bool)
(declare-fun maps_auth_to (String String) Bool)
(declare-fun maps_unauth_to (String String) Bool)
(declare-fun resource_policy_action (String String) Bool)
(declare-fun resource_policy_principal (String String) Bool)
(declare-fun self_registration_unrestricted (String String) Bool)
(declare-fun trusts_service (String String) Bool)

; --- Facts ---
;; fact_id: b965070a04f7
;; projector: controlFacts
;; path: severity
(assert (has_severity "CTL.S3.PUBLIC.001" "critical"))
;; fact_id: 183507c537b0
;; projector: controlFacts
;; path: type
(assert (has_type "CTL.S3.PUBLIC.001" "unsafe_state"))
;; fact_id: 031e07f63e1e
;; projector: assetFacts
;; path: type
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_type "arn:aws:s3:::acme-customer-uploads" "aws_s3_bucket"))
;; fact_id: 6b816c288514
;; projector: assetFacts
;; path: vendor
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_vendor "arn:aws:s3:::acme-customer-uploads" "aws"))
;; fact_id: 0e636413131e
;; projector: assetFacts
;; path: lifecycle.first_seen
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (first_seen_at "arn:aws:s3:::acme-customer-uploads" "2026-01-01T00:00:00Z"))
;; fact_id: 26280babc0a3
;; projector: assetFacts
;; path: lifecycle.last_seen
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (last_seen_at "arn:aws:s3:::acme-customer-uploads" "2026-01-08T00:00:00Z"))
;; fact_id: 2a50ea65f55f
;; projector: stringifiedPolicyFacts
;; path: properties.storage.policy_json → (parsed JSON) → Statement[0].Principal
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (resource_policy_principal "arn:aws:s3:::acme-customer-uploads" "*"))
;; fact_id: bbe38d79189f
;; projector: stringifiedPolicyFacts
;; path: properties.storage.policy_json → (parsed JSON) → Statement[0].Action
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (resource_policy_action "arn:aws:s3:::acme-customer-uploads" "s3:GetObject"))
;; fact_id: 0182cebcf9f1
;; projector: propertyFacts
;; path: properties.storage.access.public_read
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_public_read "arn:aws:s3:::acme-customer-uploads" "true"))
;; fact_id: c4ed016554e4
;; projector: propertyFacts
;; path: properties.storage.access.public_list
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_public_list "arn:aws:s3:::acme-customer-uploads" "false"))
;; fact_id: 3075001bc55a
;; projector: propertyFacts
;; path: properties.storage.access.read_via_resource
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_read_via_resource "arn:aws:s3:::acme-customer-uploads" "true"))
;; fact_id: b95bb3923301
;; projector: propertyFacts
;; path: properties.storage.controls.public_access_fully_blocked
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_public_access_blocked "arn:aws:s3:::acme-customer-uploads" "false"))
;; fact_id: 30d6a9d2cf40
;; projector: tagFacts
;; path: properties.storage.tags.data_classification
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_tag "arn:aws:s3:::acme-customer-uploads" "data_classification=confidential"))
;; fact_id: bc56657c8b25
;; projector: exposureFacts
;; path: temporal.windows[0]
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (has_exposure_window "arn:aws:s3:::acme-customer-uploads" "true"))
;; fact_id: 0162f9257196
;; projector: exposureFacts
;; path: contributing_controls
;; captured: 2026-01-08T00:00:00Z
;; age: 604800s (7d)
(assert (contributed_by "arn:aws:s3:::acme-customer-uploads" "CTL.S3.PUBLIC.001"))

; --- Closed-world axioms ---
; Each axiom restricts the predicate to its asserted positive facts.
; For predicates with no facts, the axiom asserts the predicate is
; false everywhere.
(assert (forall ((x String) (y String)) (not (allows_unauthenticated x y))))
(assert (forall ((x String) (y String)) (not (can_assume x y))))
(assert (forall ((x String) (y String)) (=> (contributed_by x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "CTL.S3.PUBLIC.001")))))
(assert (forall ((x String) (y String)) (not (cross_account_assumes x y))))
(assert (forall ((x String) (y String)) (=> (first_seen_at x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "2026-01-01T00:00:00Z")))))
(assert (forall ((x String) (y String)) (not (has_access_advisor_available x y))))
(assert (forall ((x String) (y String)) (not (has_action x y))))
(assert (forall ((x String) (y String)) (not (has_advanced_security_enabled x y))))
(assert (forall ((x String) (y String)) (not (has_advanced_security_mode x y))))
(assert (forall ((x String) (y String)) (not (has_agent_action_group_count x y))))
(assert (forall ((x String) (y String)) (not (has_agent_guardrail x y))))
(assert (forall ((x String) (y String)) (not (has_agent_iac_managed x y))))
(assert (forall ((x String) (y String)) (not (has_agent_invocation_logging x y))))
(assert (forall ((x String) (y String)) (not (has_agent_lambda_scope_broad x y))))
(assert (forall ((x String) (y String)) (not (has_agent_s3_scope_broad x y))))
(assert (forall ((x String) (y String)) (not (has_bucket_exists x y))))
(assert (forall ((x String) (y String)) (not (has_bucket_owned x y))))
(assert (forall ((x String) (y String)) (not (has_condition x y))))
(assert (forall ((x String) (y String)) (not (has_condition_value x y))))
(assert (forall ((x String) (y String)) (not (has_customer_can_revoke x y))))
(assert (forall ((x String) (y String)) (not (has_data_event_logging x y))))
(assert (forall ((x String) (y String)) (not (has_declared_role_type x y))))
(assert (forall ((x String) (y String)) (not (has_delegated_principal x y))))
(assert (forall ((x String) (y String)) (not (has_delegation_external_principals x y))))
(assert (forall ((x String) (y String)) (not (has_delegation_review_expired x y))))
(assert (forall ((x String) (y String)) (not (has_delegation_scope_exceeded x y))))
(assert (forall ((x String) (y String)) (not (has_delegation_scope_exceeded_for x y))))
(assert (forall ((x String) (y String)) (not (has_deny_action x y))))
(assert (forall ((x String) (y String)) (not (has_deny_resource x y))))
(assert (forall ((x String) (y String)) (not (has_exposed_repo_artifacts x y))))
(assert (forall ((x String) (y String)) (=> (has_exposure_window x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "true")))))
(assert (forall ((x String) (y String)) (not (has_forbidden_category x y))))
(assert (forall ((x String) (y String)) (not (has_forbidden_state x y))))
(assert (forall ((x String) (y String)) (not (has_ghost_trigger x y))))
(assert (forall ((x String) (y String)) (not (has_incompatible_categories x y))))
(assert (forall ((x String) (y String)) (not (has_incompatible_pair x y))))
(assert (forall ((x String) (y String)) (not (has_instance_dual_homed x y))))
(assert (forall ((x String) (y String)) (not (has_instance_profile_arn x y))))
(assert (forall ((x String) (y String)) (not (has_instance_profile_overprivileged x y))))
(assert (forall ((x String) (y String)) (not (has_instance_state x y))))
(assert (forall ((x String) (y String)) (not (has_instance_stopped_age_days x y))))
(assert (forall ((x String) (y String)) (not (has_instance_stopped_aged x y))))
(assert (forall ((x String) (y String)) (not (has_instance_vpc x y))))
(assert (forall ((x String) (y String)) (not (has_intent_mismatch x y))))
(assert (forall ((x String) (y String)) (not (has_intent_rationale x y))))
(assert (forall ((x String) (y String)) (not (has_kb_source_encrypted x y))))
(assert (forall ((x String) (y String)) (not (has_kb_target_bucket x y))))
(assert (forall ((x String) (y String)) (not (has_list_via_resource x y))))
(assert (forall ((x String) (y String)) (not (has_logging_enabled x y))))
(assert (forall ((x String) (y String)) (not (has_mfa_enforced x y))))
(assert (forall ((x String) (y String)) (not (has_peering_dns_resolution x y))))
(assert (forall ((x String) (y String)) (not (has_peering_id x y))))
(assert (forall ((x String) (y String)) (not (has_peering_peer_account x y))))
(assert (forall ((x String) (y String)) (not (has_peering_peer_in_org x y))))
(assert (forall ((x String) (y String)) (not (has_peering_peer_vpc x y))))
(assert (forall ((x String) (y String)) (not (has_peering_route_broad x y))))
(assert (forall ((x String) (y String)) (not (has_peering_route_target x y))))
(assert (forall ((x String) (y String)) (not (has_peering_status x y))))
(assert (forall ((x String) (y String)) (not (has_permission_action x y))))
(assert (forall ((x String) (y String)) (not (has_permission_drift_threshold_exceeded x y))))
(assert (forall ((x String) (y String)) (not (has_permission_resource x y))))
(assert (forall ((x String) (y String)) (not (has_privilege_level x y))))
(assert (forall ((x String) (y String)) (=> (has_public_access_blocked x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "false")))))
(assert (forall ((x String) (y String)) (=> (has_public_list x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "false")))))
(assert (forall ((x String) (y String)) (=> (has_public_read x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "true")))))
(assert (forall ((x String) (y String)) (=> (has_read_via_resource x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "true")))))
(assert (forall ((x String) (y String)) (not (has_resource x y))))
(assert (forall ((x String) (y String)) (not (has_role_age_days x y))))
(assert (forall ((x String) (y String)) (=> (has_severity x y) (and (= x "CTL.S3.PUBLIC.001") (= y "critical")))))
(assert (forall ((x String) (y String)) (=> (has_tag x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "data_classification=confidential")))))
(assert (forall ((x String) (y String)) (not (has_total_services_accessible x y))))
(assert (forall ((x String) (y String)) (not (has_trigger_lambda_exists x y))))
(assert (forall ((x String) (y String)) (not (has_trigger_type x y))))
(assert (forall ((x String) (y String)) (=> (has_type x y) (or (and (= x "CTL.S3.PUBLIC.001") (= y "unsafe_state")) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "aws_s3_bucket"))))))
(assert (forall ((x String) (y String)) (not (has_unknown_delegated_principal x y))))
(assert (forall ((x String) (y String)) (not (has_unknown_delegation x y))))
(assert (forall ((x String) (y String)) (not (has_unused_service x y))))
(assert (forall ((x String) (y String)) (not (has_unused_service_ratio x y))))
(assert (forall ((x String) (y String)) (not (has_upload_key_mode x y))))
(assert (forall ((x String) (y String)) (not (has_uses_access_key_id x y))))
(assert (forall ((x String) (y String)) (=> (has_vendor x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "aws")))))
(assert (forall ((x String) (y String)) (not (has_vendor_can_make_public x y))))
(assert (forall ((x String) (y String)) (not (has_vendor_put_bucket_policy x y))))
(assert (forall ((x String) (y String)) (not (has_webhook_config_access x y))))
(assert (forall ((x String) (y String)) (not (is_decommissioned x y))))
(assert (forall ((x String) (y String)) (not (is_provisioned x y))))
(assert (forall ((x String) (y String)) (=> (last_seen_at x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "2026-01-08T00:00:00Z")))))
(assert (forall ((x String) (y String)) (not (maps_auth_to x y))))
(assert (forall ((x String) (y String)) (not (maps_unauth_to x y))))
(assert (forall ((x String) (y String)) (=> (resource_policy_action x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "s3:GetObject")))))
(assert (forall ((x String) (y String)) (=> (resource_policy_principal x y) (and (= x "arn:aws:s3:::acme-customer-uploads") (= y "*")))))
(assert (forall ((x String) (y String)) (not (self_registration_unrestricted x y))))
(assert (forall ((x String) (y String)) (not (trusts_service x y))))
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
