# aws iam list-groups  ->  one base aws_iam_group asset per group.
# The list call carries only identity (name/arn); computed signals
# (has_inline_policies, has_admin_policy, member_count, policy_count,
# has_policies_no_members) come from per-group enrichment filters and merge in by
# id. Shape follows the committed nccgroup convention: properties.identity.group.
.Groups[] | {
  id: .Arn,
  type: "aws_iam_group",
  vendor: "aws",
  properties: { identity: { group: {
    name: .GroupName
  } } }
}
