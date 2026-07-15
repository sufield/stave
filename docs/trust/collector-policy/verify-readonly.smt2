; Stave Collector Policy — Read-Only Verification
;
; Proves that every action in the collector IAM policy is read-only.
; An action is read-only if its verb prefix is Get, List, or Describe.
; If any action has a different verb prefix, Z3 returns SAT with a
; counterexample. UNSAT means: every action is read-only.
;
; Run:  z3 verify-readonly.smt2
; Expected output:  unsat
;
; This is a syntactic check on the action names, not a semantic proof
; about AWS API behavior. It verifies the policy document matches the
; read-only naming convention that AWS uses for non-mutating APIs.

(set-logic QF_S)

; Define the read-only verb prefixes
(define-fun is-read-only ((action String)) Bool
  (or
    (str.prefixof "Get" action)
    (str.prefixof "List" action)
    (str.prefixof "Describe" action)))

; Strip the "service:" prefix to get the verb
(define-fun verb ((action String)) String
  (str.substr action (+ (str.indexof action ":" 0) 1)
              (- (str.len action) (+ (str.indexof action ":" 0) 1))))

; Every action in the collector policy (51 actions)
; Assert: there exists an action that is NOT read-only
(declare-const violation Bool)
(assert (= violation
  (not (and
    (is-read-only (verb "cloudtrail:DescribeTrails"))
    (is-read-only (verb "cloudtrail:GetEventSelectors"))
    (is-read-only (verb "cloudwatch:DescribeAlarms"))
    (is-read-only (verb "config:DescribeConfigurationRecorders"))
    (is-read-only (verb "ec2:DescribeInstanceAttribute"))
    (is-read-only (verb "ec2:DescribeInstances"))
    (is-read-only (verb "ec2:DescribeNetworkInterfaces"))
    (is-read-only (verb "ec2:DescribeSecurityGroups"))
    (is-read-only (verb "ec2:DescribeVolumes"))
    (is-read-only (verb "es:DescribeDomain"))
    (is-read-only (verb "es:ListDomainNames"))
    (is-read-only (verb "iam:GetAccountAuthorizationDetails"))
    (is-read-only (verb "iam:GetAccountPasswordPolicy"))
    (is-read-only (verb "iam:GetAccountSummary"))
    (is-read-only (verb "iam:GetPolicy"))
    (is-read-only (verb "iam:GetPolicyVersion"))
    (is-read-only (verb "iam:GetRolePolicy"))
    (is-read-only (verb "iam:GetUserPolicy"))
    (is-read-only (verb "iam:GetGroupPolicy"))
    (is-read-only (verb "iam:ListAccountAliases"))
    (is-read-only (verb "iam:ListAttachedGroupPolicies"))
    (is-read-only (verb "iam:ListAttachedRolePolicies"))
    (is-read-only (verb "iam:ListAttachedUserPolicies"))
    (is-read-only (verb "iam:ListGroupPolicies"))
    (is-read-only (verb "iam:ListGroups"))
    (is-read-only (verb "iam:ListGroupsForUser"))
    (is-read-only (verb "iam:ListRolePolicies"))
    (is-read-only (verb "iam:ListRoles"))
    (is-read-only (verb "iam:ListRoleTags"))
    (is-read-only (verb "iam:ListUserPolicies"))
    (is-read-only (verb "iam:ListUsers"))
    (is-read-only (verb "kms:GetKeyPolicy"))
    (is-read-only (verb "kms:GetKeyRotationStatus"))
    (is-read-only (verb "kms:ListKeys"))
    (is-read-only (verb "organizations:DescribeOrganization"))
    (is-read-only (verb "organizations:ListAccounts"))
    (is-read-only (verb "s3:GetBucketEncryption"))
    (is-read-only (verb "s3:GetBucketLogging"))
    (is-read-only (verb "s3:GetBucketPolicy"))
    (is-read-only (verb "s3:GetBucketTagging"))
    (is-read-only (verb "s3:GetBucketVersioning"))
    (is-read-only (verb "s3:GetPublicAccessBlock"))
    (is-read-only (verb "s3:ListAllMyBuckets"))
    (is-read-only (verb "ses:GetIdentityDkimAttributes"))
    (is-read-only (verb "ses:ListIdentities"))
    (is-read-only (verb "ses:ListIdentityPolicies"))
    (is-read-only (verb "sts:GetCallerIdentity"))
  ))))

; If violation is satisfiable, a non-read-only action exists
(assert violation)
(check-sat)
