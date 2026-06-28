# Per-role attached managed policies, merged into the base role asset by id.
#
# INPUT CONTRACT: aws iam list-attached-role-policies returns only
# {"AttachedPolicies":[...]} with no role identity, so the collector annotates it
# with the role ARN (the merge id):
#   {"RoleArn":"arn:aws:iam::…:role/<name>","AttachedPolicies":[{"PolicyArn":…}]}
# A file without "RoleArn" is skipped (no id to merge onto).
#
# Mapping matches scripts/aws-snapshot.sh: attached_policy_arns is the list of
# PolicyArn; is_admin_equivalent is the coarse "any == AdministratorAccess" check.
{
  id: .RoleArn,
  type: "aws_iam_role",
  vendor: "aws",
  properties: { identity: {
    attached_policy_arns: [ (.AttachedPolicies // [])[].PolicyArn ],
    is_admin_equivalent: ([ (.AttachedPolicies // [])[].PolicyArn ]
      | any(. == "arn:aws:iam::aws:policy/AdministratorAccess"))
  } }
}
